rule infected_09_10_18_phishing_smartsheet_htaccess {
  meta:
    description = "account - file .htaccess"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-12"
    hash1       = "797d267648e4045ac790950c234fc6f33d8c20ae51f8c4d6be1a233ab3684c05"

  strings:
    $s1  = "deny from blogger.com" fullword ascii
    $s2  = "deny from blogs.eset-la.com" fullword ascii
    $s3  = "deny from infospyware.com" fullword ascii
    $s4  = "deny from opera.com" fullword ascii
    $s5  = "deny from fireeye.com" fullword ascii
    $s6  = "Deny from morgue1.corp.yahoo.com" fullword ascii
    $s7  = "Deny from crawl8-public.alexa.com" fullword ascii
    $s8  = "deny from wilderssecurity.com" fullword ascii
    $s9  = "Deny from tracerlock.com" fullword ascii
    $s10 = "deny from malwaredomainlist.com" fullword ascii
    $s11 = "Deny from pixnat09.whizbang.com" fullword ascii
    $s12 = "deny from community.norton.com" fullword ascii
    $s13 = "deny from welivesecurity.com" fullword ascii
    $s14 = "deny from virustotal.com" fullword ascii
    $s15 = "deny from alienvault.com" fullword ascii
    $s16 = "deny from minotauranalysis.com" fullword ascii
    $s17 = "Deny from pixnat06.whizbang.com" fullword ascii
    $s18 = "Deny from hanta.yahoo.com" fullword ascii
    $s19 = "deny from gdatasoftware.com" fullword ascii
    $s20 = "Deny from zeus.nj.nec.com" fullword ascii

  condition:
    (uint16(0) == 0x6564 and
      filesize < 300KB and
      (8 of them)
    ) or (all of them)
}