rule sig_20160426_460e537e57704d28da99dee35675d368 {
  meta:
    description = "datamaliciousorder - file 20160426_460e537e57704d28da99dee35675d368.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba85f9a437044a3a61f19a538fc46d2737e313cedb0ae21efdc3a2fb6ae4ed8"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('14 336(509,508,51" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('14 336(509,508,51" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}