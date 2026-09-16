rule htaccess {
  meta:
    description = "case127 - file htaccess"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "12a5ff666829220eeadb0496eea0481308387824ea6e3fcaabfe4b1d449a7565"

  strings:
    $x1  = "RewriteCond %{HTTP_USER_AGENT} webclipping [NC,OR] # bandwidth waster webclipping.com " fullword ascii
    $x2  = "RewriteCond %{HTTP_USER_AGENT} madlyrics [NC,OR] # Winamp downloader " fullword ascii
    $x3  = "RewriteCond %{HTTP_USER_AGENT} picsearch [NC,OR] # Picture Downloader " fullword ascii
    $x4  = "RewriteCond %{HTTP_USER_AGENT} psbot [NC,OR] # Picture Downloader " fullword ascii
    $x5  = "RewriteCond %{HTTP_USER_AGENT} dloader [NC,OR] # unknown downloader " fullword ascii
    $x6  = "RewriteCond %{HTTP_USER_AGENT} hloader [NC,OR] # unknown downloader " fullword ascii
    $x7  = "RewriteCond %{HTTP_USER_AGENT} trademark [NC,OR] # bandwidth waster trademarktracker.com " fullword ascii
    $x8  = "RewriteCond %{HTTP_USER_AGENT} \"addresses\\.com\" [NC,OR] # spambot " fullword ascii
    $s9  = "RewriteCond %{HTTP_USER_AGENT} e?mail.?(collector|magnet|reaper|siphon|sweeper|harvest|collect|wolf) [NC,OR] # spambots " fullword ascii
    $s10 = "RewriteCond %{HTTP_USER_AGENT} web.?(auto|bandit|collector|copier|devil|downloader|fetch|hook|mole|miner|mirror|reaper|sauger|su" ascii
    $s11 = "RewriteCond %{HTTP_USER_AGENT} ConveraCrawler [NC,OR] # convera.com " fullword ascii
    $s12 = "RewriteCond %{HTTP_USER_AGENT} web.?(auto|bandit|collector|copier|devil|downloader|fetch|hook|mole|miner|mirror|reaper|sauger|su" ascii
    $s13 = "RewriteCond %{HTTP_USER_AGENT} linksmanager [NC,OR] # linksmanager.com spambot " fullword ascii
    $s14 = "RewriteCond %{HTTP_USER_AGENT} girafabot [NC,OR] # girafa.com SE thingy " fullword ascii
    $s15 = "RewriteCond %{HTTP_USER_AGENT} cjnetworkquality [NC,OR] # cj.com bot " fullword ascii
    $s16 = "RewriteCond %{HTTP_USER_AGENT} twiceler [NC,OR] # www.cuill.com " fullword ascii
    $s17 = "RewriteCond %{HTTP_USER_AGENT} ocelli [NC,OR] # www.globalspec.com " fullword ascii
    $s18 = "RewriteCond %{HTTP_USER_AGENT} \"mozilla\\(ie compatible\\)\" [NC,OR] # BS agent " fullword ascii
    $s19 = "RewriteCond %{HTTP_USER_AGENT} \"www.abot.com\" [NC,OR] " fullword ascii
    $s20 = "RewriteCond %{HTTP_USER_AGENT} convera [NC,OR] # convera.com " fullword ascii

  condition:
    (uint16(0) == 0x4c3c and
      filesize < 100KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}