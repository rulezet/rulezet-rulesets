rule _20160518_0b11ee474fb81071b6c8c6a60d2bcc95_20160518_1a6f108f9a41_1273 {
  meta:
    description = "datamaliciousorder - from files 20160518_0b11ee474fb81071b6c8c6a60d2bcc95.js, 20160518_1a6f108f9a4116b1f16b2f53e11a10ac.js, 20160518_1df7886e500ac7b0dfc04f059df43bdb.js, 20160519_b3e23df6d56d27f44e0c9d679bb91b34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79ae942d8769f4d6eec498e5a4eada6fccb0d0add2727833ce0d0c44eac65db2"
    hash2       = "a438f005ce21ff9688a213d82b23578a85a49ddc8886aaa9defcf8f1b32b4b3f"
    hash3       = "20e53c835d2200365faf75d1e66da114f0a5bf7f1b01adbda07782398a2a5b74"
    hash4       = "52d06c22a4ab55732870cb1a11ad5213ee2f91b30c94b84241c93d9fdb154820"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* x  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* x  */;};" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* x  */, A8name /* x  *" ascii
    $s4 = "dot1 /* x  */= true;/* x  */" fullword ascii
    $s5 = "newtonsCradle1 /* x  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}