rule _20160802_0d6f8d2da3245e99dd3f81969e56e13f_20160802_1134bc0ad16c_916 {
  meta:
    description = "datamaliciousorder - from files 20160802_0d6f8d2da3245e99dd3f81969e56e13f.js, 20160802_1134bc0ad16c74803a221c832a0e3a9e.js, 20160802_5c6f4b05f7ae6e7f80c4c82143e614d3.js, 20160802_c63f9f732a11c718da1e142bef678e14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc1dad1193b954be315ab7e10ab799113b88015f80a293931ecdba5021c330b7"
    hash2       = "474b73e2a3a9a150cfa4a4d4e72c9a6262f84af25220ef80c1ee3b49c81ff7e3"
    hash3       = "1f8a3564975cc7479ecbc1863cee5dcb08027adfa323eb8e0e11ce87e87d0326"
    hash4       = "6ffe5bfec1c5d7b367de157c4483426c3cb01741e164f48abb130b4594d0b0c8"

  strings:
    $s1 = "r\\x0avar Uh6 = \"len\\x22 + \\x22\\x22;\\r\\nfunc\\x74i\\x6f\\x6e KEx3(TEw){return TEw;};v\\x61r Aa9 =\\x20\"GET\"\\x20+ \"\"" ascii
    $s2 = "\\x74ion ST\\x760(Ra0){return Ra0;};var\\x20TV\\x723\\x20= \"e\" + \"\";\\r\\nva\\x72 VTk0 =\\x20\"wr\\x69t\" + \\x22\";\\r\\nva" ascii
    $s3 = "m\" + \"\";\\r\\x0avar Y\\x76 = \"St\" +\\x20\"\";\\r\\nva\\x72 XOs = \"DB\\x2e\" + \"\"\\x3b\\r\\n\\x66unction\\x20Vw3(NAa){ret" ascii
    $s4 = "nvar D\\x72 = \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\r\\x0a\\x76ar\\x20Bv8 = \\x22len\" + \"\";\\r\\nfunction Zk(KHz9" ascii
    $s5 = "\";\\r\\nfunction DEk0\\x28Ja0\\x29{return Ja0;};functi\\x6fn\\x20P\\x4ah(\\x4dTj4){\\x72etur\\x6e MTj4;};va\\x72 RVy = \"e\" + " ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}