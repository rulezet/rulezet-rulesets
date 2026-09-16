rule sig_20160426_3d8b9c055a53c958727dab9235d8ab22 {
  meta:
    description = "datamaliciousorder - file 20160426_3d8b9c055a53c958727dab9235d8ab22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba87b35be0b3cdd71cef7e9ccbc8cf6dbd406cead320e4064f759b6a909d6aab"

  strings:
    $s1 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('15 348(){8 161=57" ascii
    $s2 = "eval(function(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+c+'\\\\b','g'),k[c])}}return p}('15 348(){8 161=57" ascii

  condition:
    uint16(0) == 0x7665 and
    all of them
}