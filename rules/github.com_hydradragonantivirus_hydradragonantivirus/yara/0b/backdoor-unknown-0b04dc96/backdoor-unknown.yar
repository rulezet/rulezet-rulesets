rule backdoor_unknown {
  meta:
    description = "work1 - file backdoor_unknown.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "291ff52840c65884ef97436f2ae472228f08240f0569f6bcc45d6e2b026b190f"

  strings:
    $x1  = "else $ttxt = get_data_yo(\"http://ferm2018all.com/lnk/gen/index.php?key=$tkey&g=$group&lang=$lang&page=$page&cldw=$cl" fullword ascii
    $x2  = "$desc = get_data_yo(\"http://ferm2018all.com//lnk/gen/desc.php?key=$tkey&desc=$group\");" fullword ascii
    $s3  = "$twork = file_get_contents('http://ferm2018all.com/lnk/up/sh.txt');" fullword ascii
    $s4  = "$clkeys = get_data_yo(\"http://ferm2018all.com/lnk/gen/keys/$kgroup.keys\");" fullword ascii
    $s5  = "$ll = get_data_yo(\"http://ferm2018all.com/lnk/tuktuk.php?d=$donor&cldw=$cldw&dgrp=$algo\");" fullword ascii
    $s6  = "$fbots = get_data_yo(\"http://ferm2018all.com/lnk/bots.dat\");" fullword ascii
    $s7  = "$my_content = str_replace('</head>', \"<meta name=\\\"description\\\" content=\\\"$desc\\\">" fullword ascii
    $s8  = "$gtxt = file_get_contents(\"{$eb}{$st}/$page.txt\");" fullword ascii
    $s9  = "if ($cldw) file_put_contents(\"{$eb}{$st}/cldwmap.txt\", $newcllink, FILE_APPEND);" fullword ascii
    $s10 = ">$rating-5</span> stars based on\\n<span itemprop=\\\"reviewCount\\\">$rcount</span> reviews\\n</div>\\n</div>\\n\";" fullword ascii
    $s11 = "else $ttxt = get_data_yo(\"http://ferm2018all.com/lnk/gen/index.php?key=$tkey&g=$group&lang=$lang&page=$page&cldw=$cldw&dd=$ddom" ascii
    $s12 = "$my_content = preg_replace('#<div class=\"post-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, " fullword ascii
    $s13 = "if (file_put_contents(\"{$eb}xml.php\", $twork)) echo \"success!<br><a href=/{$eb}xml.php>go</a>\";" fullword ascii
    $s14 = "file_put_contents(\"{$eb}{$st}/$page.txt\", \"$title|$desc|$txt|$h1\");" fullword ascii
    $s15 = "$my_content = preg_replace('#<div class=\"post-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, 1);" fullword ascii
    $s16 = "$my_content = preg_replace(\"#<meta name=[\\\"\\']{1}description(.*)\\>#iUs\", '', $my_content);" fullword ascii
    $s17 = "$my_content = preg_replace(\"#<meta name=[\\\"\\']{1}keywords(.*)\\>#iUs\", '', $my_content);" fullword ascii
    $s18 = "elseif (!preg_match('#<title>(.*)404(.*)#i', $my_content) && !preg_match('#<title>(.*)not found(.*)#i', $my_content)) {" fullword ascii
    $s19 = "$my_content = preg_replace('#<div id=\"entry-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, 1)" fullword ascii
    $s20 = "$my_content = preg_replace('#<div id=\"main-content\">(.*)</div>#iUs', \"<div>\\n$txt\\n</div>\", $my_content, 1);" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 50KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}