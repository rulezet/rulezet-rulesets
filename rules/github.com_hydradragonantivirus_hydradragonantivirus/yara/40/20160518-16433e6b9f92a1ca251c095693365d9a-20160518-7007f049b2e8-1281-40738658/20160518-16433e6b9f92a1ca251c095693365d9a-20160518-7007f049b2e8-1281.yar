rule _20160518_16433e6b9f92a1ca251c095693365d9a_20160518_7007f049b2e8_1281 {
  meta:
    description = "datamaliciousorder - from files 20160518_16433e6b9f92a1ca251c095693365d9a.js, 20160518_7007f049b2e8ecb05ff2ad29c089e2a4.js, 20160518_bf70d7d2248e63d0dba192f2d4534e42.js, 20160519_c8456fb31c653b989b8fa446b8eb002a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0804f7ba5a9f1ae3b4b446f52b1c20302578ca1b361bc9ed03c374102f66d7ec"
    hash2       = "6ee3bac1ca645287aa2a6b0dd09e28ec980fbc907757e31897772af3f07bcf78"
    hash3       = "1b5d0861350407c4af8de8c2518d2d22d26fa8837bdf61465714068804ee4eea"
    hash4       = "7f9fbc4e277623b73720d6d0daf14f7bf6f67102ed69bd600849dff68af31799"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* n  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* n  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* n  */, A8name /* n  *" ascii
    $s4 = "dot1 /* n  */= true;/* n  */" fullword ascii
    $s5 = "function sDiv2(){return newtonsCradle0 /* n  */;};" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}