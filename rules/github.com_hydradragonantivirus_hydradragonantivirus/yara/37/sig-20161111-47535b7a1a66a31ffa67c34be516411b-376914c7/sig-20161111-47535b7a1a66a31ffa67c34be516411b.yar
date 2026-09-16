rule sig_20161111_47535b7a1a66a31ffa67c34be516411b {
  meta:
    description = "datamaliciousorder - file 20161111_47535b7a1a66a31ffa67c34be516411b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a2de4d74e1210dd9144feeb642afb2227cf14d75d9271e79bc87067f3ae29f4"

  strings:
    $s1 = "    var JSv3 = [YPu0 + \"iwebsdns.com/116peo\",YPu0 + \"spoiltgirlsclub.com/x6usth1\",YPu0 + \"jalapodist.net/3xx77m97\",YPu0 + " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}