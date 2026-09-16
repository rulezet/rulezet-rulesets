rule _20160802_1c182136b90a58f5092c28b7225f7c25_20160802_89413a6b8efe_1020 {
  meta:
    description = "datamaliciousorder - from files 20160802_1c182136b90a58f5092c28b7225f7c25.js, 20160802_89413a6b8efedd4c127c38bfd4e78f38.js, 20160802_8d2386f7cd2c8ade2d65350b53722cbc.js, 20160802_acc0916968f6f0784b234a6efa60f799.js, 20160802_dbc0c92b70e88a12f7e2301ac83fcad4.js, 20160802_e8849e3571c4e2a1c79b34aaa181822b.js, 20160802_ee2839601907846df1380b0738e515ce.js, 20160802_f10d5bda1d7b27fd7ca39aa173a886b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209721d907c797cc6824ffb89d4905430c0a7b7e6e7f93aedcaffe4d80f38068"
    hash2       = "da1f3ce75fe404d2a90591c3272a2bbf79221e5b49790bbce6ef4f1c6b7572ae"
    hash3       = "cb981c4a5bbb74592ef414f6e026630632d93d57d553ec7e24f668c23417f0f8"
    hash4       = "e00c651256b31fd8a76a3bb05bac535cc06081af4079fa1034fab7c5a603b5a6"
    hash5       = "ec440086a9bc8a20b4d94942efdaf81704c4d5d199a4971f4c6ad7250da9a95e"
    hash6       = "cb20921e85a6bbb77a2583e8aeb5ba46fa9eb6552f766ca4ca48341e5230f1f9"
    hash7       = "adce6bae397465621c2dbf4b7310cf1281aaeb7aeeaa6aa3f9798687de59e9b0"
    hash8       = "951306314da81d72ed25759f2eae6e482cdc7a7d43e3c65e5dbcad6f21dfc4a2"

  strings:
    $s1 = "\"\";\\x0d\\n\\x76ar Uh6 = \"len\"\\x20+ \"\\x22\\x3b\\r\\nfunct\\x69o\\x6e\\x20KEx3(TEw){return TEw;};va\\x72 Aa9 = \\x22GET\" " ascii
    $s2 = "pe\" \\x2b \"\";\\r\\nvar \\x4aW\\x7a3 =\\x20\"n\" + \\x22\";\\x0d\\n\\x76ar APp7 = \"ope\" + \"\";\\r\\n\\x66unction Xp6(Ik){re" ascii
    $s3 = "x22ream\" + \"\";\\r\\n\\x76ar Yv\\x20= \"St\" + \\x22\";\\r\\nvar\\x20XOs = \"DB.\\x22 + \"\";\\x0d\\nf\\x75nction \\x56w3(NAa)" ascii
    $s4 = "\"\";\\r\\nvar Dr\\x20= \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\r\\n\\x76\\x61r \\x42v8 = \"\\x6cen\" + \"\";\\r\\nfun" ascii
    $s5 = "66unct\\x69on STv\\x30(Ra0){return Ra0;};var \\x54Vr\\x33 \\x3d \"e\" + \"\";\\r\\nvar\\x20VTk0 = \\x22wri\\x74\" + \"\\x22;\\r" ascii
    $s6 = " + \"\";\\r\\nfunction DEk\\x30(Ja\\x29{return Ja;};functio\\x6e \\x50J\\x68(M\\x54j4){r\\x65turn\\x20MTj4;};var\\x20RVy = \"e\"" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}