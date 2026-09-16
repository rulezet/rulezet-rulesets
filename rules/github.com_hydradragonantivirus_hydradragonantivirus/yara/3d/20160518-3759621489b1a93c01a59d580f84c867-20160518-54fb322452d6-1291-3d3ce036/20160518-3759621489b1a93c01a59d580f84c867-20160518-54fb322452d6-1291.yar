rule _20160518_3759621489b1a93c01a59d580f84c867_20160518_54fb322452d6_1291 {
  meta:
    description = "datamaliciousorder - from files 20160518_3759621489b1a93c01a59d580f84c867.js, 20160518_54fb322452d68ab7bebf79258f017bcd.js, 20160518_61200134589485ea3669a7f07577a842.js, 20160519_160d84f57734d592f3604ab334d346c2.js, 20160519_166e9413a4472dcbae558e364f99e22e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5002996cfb97d359fd3cb9cf96feb228e93505192fd8896cc0c3c8c4cf5e4daf"
    hash2       = "c4402e34f512aad66ad3b42f75a718d8d9d523162a5f408f995eebe4cb95ade6"
    hash3       = "1208037da7fd3eb8685f32c1a04832239b1623ce121ae2cbe353aea29e28f946"
    hash4       = "35cac06134463a5a26523ba02f80e3325e0271d27e0ab86f3a6ff01f2b8dff0a"
    hash5       = "b3f6eaa8675f1c9320ee7f1790f0da9f074cbbb0ae9b2164adcb7520d69ecdbe"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* v  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* v  */= true;/* v  */" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* v  */, A8name /* v  *" ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* v  */;};" fullword ascii
    $s5 = "newtonsCradle1 /* v  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}