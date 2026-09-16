rule _20160518_15f7d9268e32d1055e2a004c2c71f95a_20160518_84b8f969b9e9_1280 {
  meta:
    description = "datamaliciousorder - from files 20160518_15f7d9268e32d1055e2a004c2c71f95a.js, 20160518_84b8f969b9e962681c952b38fa772113.js, 20160518_8d2afb6676ebb5780110bd96d4a83de3.js, 20160518_97ea8342b3f053a20ddfee6cafaadfeb.js, 20160518_9f1eea616bef392a76c4bbfccd5a5906.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2c3acbbdf19345a48810b8569e01d51dc041386a44f20a1197fe8075320a4a6"
    hash2       = "d7b179df540ecd2a71b3a03625ce6016f3acad4ab6c0a018514fe86abbd637e7"
    hash3       = "3aed71198f34d39104f2eeed15978b7d7dadb4ca09af57e1c864c5fc45c3e04a"
    hash4       = "f9b093f924ca8bfefbd9ed998cc114dcf40887b94790377b4fd4def7bddb271c"
    hash5       = "f9460e76d5bc29d599bd5b6be9c6da3686b8c4d434628c3aa1916ea621ba5ec5"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* Y  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* Y  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* Y  */, A8name /* Y  *" ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* Y  */;};" fullword ascii
    $s5 = "dot1 /* Y  */= true;/* Y  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}