rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_98f234a378a6_3668 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash3       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"

  strings:
    $s1 = "ction f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s2 = "n \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s3 = "00(){return \"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\"" ascii
    $s4 = "rn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(fu" ascii
    $s5 = "0(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";" ascii
    $s6 = "(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}