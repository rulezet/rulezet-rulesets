rule _20160802_123dc13112ad0f6a3b64f12e9dc28bf5_20160802_94de71b40c6a_1094 {
  meta:
    description = "datamaliciousorder - from files 20160802_123dc13112ad0f6a3b64f12e9dc28bf5.js, 20160802_94de71b40c6a5884c90d612e53d0c91a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68c2033533d44cc14b45bab6eecd5231e291e45124d068ad1bb8da0b132dc8b5"
    hash2       = "31ce36c077b7274e101a682d48e4a108d0a53f3a3e6c13dc3dc93fdc21a11365"

  strings:
    $s1 = "\" + \"\";\\r\\nfu\\x6ection RTo2(Xh\\x31){return Xh1;};var Lr8 =\\x20\".inf\\x22 \\x2b \"\";\\r\\n\\x76ar QRy5 = \\x22\\x72d\" " ascii
    $s2 = "x66unction Rj3(TXh){return TXh;};var\\x20QSj5 = \"j\" + \"\";\\r\\nvar GNn \\x3d \"\\x68h\" + \"\";\\r\\nvar UAm\\x38 = \"gp\" " ascii
    $s3 = "r Vh = \"th\" \\x2b \"\\x22;\\r\\nvar WKb \\x3d \"l\\x65\\x6eg\" + \"\";\\r\\nfun\\x63ti\\x6fn Su(SHv4){return SHv4;};var Xt6 = " ascii
    $s4 = "r D\\x685 = \"\\x6cll\" + \"\";\\x0d\\nvar EGw = \\x22l\\x6c\" + \"\\x22;\\r\\x0avar Mj = \"\\x6cll\\x6cl\"\\x20+ \"\";\\r\\nfun" ascii
    $s5 = "nfunction TN\\x6b4(Xs5){return Xs\\x35;};var Xl\\x32 = \\x22an\" + \"\";\\r\\nvar MHr = \"/\\x73\\x22 + \"\";\\r\\nva\\x72 Q\\x4" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}