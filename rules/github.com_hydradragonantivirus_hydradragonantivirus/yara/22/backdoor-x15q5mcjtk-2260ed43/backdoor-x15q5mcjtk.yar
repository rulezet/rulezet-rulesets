rule backdoor_x15q5mcjtk {
  meta:
    description = "PHP - file backdoor_x15q5mcjtk.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "08d7d98c30acb6ab8dc01f1508c780156eab0be88673ecf367b8cf13165a3fb3"

  strings:
    $s1  = "curl_setopt($ch, CURLOPT_URL, \"http://\".$_GET[\"looping\"].\".9.23.3/story.php?pass=$apass&q=$_GET[id]\"); " fullword ascii
    $s2  = "'#Speedy#i', '#Teleport\\s*Pro#i', '#TurtleScanner#i', '#User-Agent#i', '#voyager#i'," fullword ascii
    $s3  = "$user_agent_to_filter = array( '#Ask\\s*Jeeves#i', '#HP\\s*Web\\s*PrintSmart#i', '#HTTrack#i', '#IDBot#i', '#Indy\\s*Library#'," fullword ascii
    $s4  = "if( FALSE !== strpos( gethostbyaddr($_SERVER['REMOTE_ADDR']), 'google')) " fullword ascii
    $s5  = "header(\"Location: http://\".$_GET[\"world\"].\".45.79.15/input/?mark=$today-$s&tpl=$tpl&engkey=$keyword\");" fullword ascii
    $s6  = "'#CFNetwork#i', '#ConveraCrawler#i','#DISCo#i', '#Download\\s*Master#i', '#FAST\\s*MetaWeb\\s*Crawler#i'," fullword ascii
    $s7  = "if (strlen($text)<5000) $text = file_get_contents(\"http://\".$_GET[\"looping\"].\".9.23.3/story.php?pass=$apass&q=$_GET[id]\");" ascii
    $s8  = "'#CFNetwork#i', '#ConveraCrawler#i','#DISCo#i', '#Download\\s*Master#i', '#FAST\\s*MetaWeb\\s*Crawle" fullword ascii
    $s9  = "//if (!strpos($_SERVER['HTTP_USER_AGENT'], \"google\")) exit;" fullword ascii
    $s10 = "'#ListChecker#i', '#MSIECrawler#i', '#NetCache#i', '#Nutch#i', '#RPT-HTTPClient#i'," fullword ascii
    $s11 = "'#rulinki\\.ru#i', '#Twiceler#i', '#WebAlta#i', '#Webster\\s*Pro#i','#www\\.cys\\.ru#i'," fullword ascii
    $s12 = "$keyword = str_replace(\"-\", \" \", $_GET[\"id\"]);" fullword ascii
    $s13 = "//$myname  = basename($_SERVER['SCRIPT_NAME'], \".php\");" fullword ascii
    $s14 = "'#Webalta#i', '#WebCopier#i', '#WebData#i', '#WebZIP#i', '#Wget#i'," fullword ascii
    $s15 = "'#scooter#i' ,'#av\\s*fetch#i' ,'#asterias#i' ,'#spiderthread revision#i' ,'#sqworm#i'," fullword ascii
    $s16 = "$keyword = \"$num_temple\";" fullword ascii
    $s17 = "$zzzzz = $_GET[\"world\"] + 171;" fullword ascii
    $s18 = "RewriteRule ^([A-Za-z0-9-]+).html$ x15q5mcjtk.php?world=5&looping=176&hl=$1 [L]\");" fullword ascii
    $s19 = "//$_GET[\"id\"] = str_replace (\"fghjkld\", \"-\", $_GET[\"id\"]);" fullword ascii
    $s20 = "$myname = $_GET[\"id\"].\".php\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (8 of them)
    ) or (all of them)
}