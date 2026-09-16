rule _20160518_224db8b993c009b956a49188027c5768_20160518_cfdb432f249d_1286 {
  meta:
    description = "datamaliciousorder - from files 20160518_224db8b993c009b956a49188027c5768.js, 20160518_cfdb432f249d940c051202fbed24e4dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e67f6e5fcf65aaf9956d2a0fbea37fb433ef85b74efebbefaae273ceec1af392"
    hash2       = "3024218e1dd163e11bdbc5d62e88a722d2fc88037bd48e4b320f9335d168eea8"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* d  */, dingy, (true, false));" fullword ascii
    $s2 = "dot1 /* d  */= true;/* d  */" fullword ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* d  */;};" fullword ascii
    $s4 = "newtonsCradle1 /* d  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* d  */, A8name /* d  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}