rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_98f234a378a6_4912 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash3       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"

  strings:
    $s1 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh" ascii
    $s2 = "turn \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s3 = "ction f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return" ascii
    $s4 = " \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(func" ascii
    $s5 = " \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MMz\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}