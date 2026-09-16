rule _20160518_01844820b9540610a4742d6492227a29_20160518_5c8a5e612270_1269 {
  meta:
    description = "datamaliciousorder - from files 20160518_01844820b9540610a4742d6492227a29.js, 20160518_5c8a5e612270ef836b32555f1e81aac0.js, 20160518_9b0be20ba2fb37ace28bcd760741d73c.js, 20160519_3152550e8cd1ccbcceff07f1483a4704.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "242dabf5d41235dfda17c3d27064be10003722278f434822d6a09049fa85c5d9"
    hash2       = "c6ad1c315feceec6616b58269b31528b186d6e9b1e591063634360c5b7e28fcd"
    hash3       = "d1f96f7d2610baffc0daca9b2dc911cb7325d37d786275c772fa0b886b952c68"
    hash4       = "7b2e6411e3747a2bc2de139ed76f1db13b7dc31c0b1d3411fd0de4efcfad027f"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* e  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* e  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* e  */, A8name /* e  *" ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* e  */;};" fullword ascii
    $s5 = "dot1 /* e  */= true;/* e  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}