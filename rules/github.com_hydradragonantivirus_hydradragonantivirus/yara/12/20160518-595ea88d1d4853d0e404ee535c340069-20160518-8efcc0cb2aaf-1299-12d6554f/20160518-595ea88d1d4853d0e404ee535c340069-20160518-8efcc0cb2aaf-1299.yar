rule _20160518_595ea88d1d4853d0e404ee535c340069_20160518_8efcc0cb2aaf_1299 {
  meta:
    description = "datamaliciousorder - from files 20160518_595ea88d1d4853d0e404ee535c340069.js, 20160518_8efcc0cb2aaf69bcaf2766ef612892fd.js, 20160519_4a769f2c35d0b4b19b421fc52f405c7c.js, 20160519_f7f5cd2a2f6871e9dbbc98e703a96282.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2de467046ec0ee5104982a8a108855cab53624bb2b7069a45bfab615b83aca62"
    hash2       = "91b7d95043e0aae31f02df5a72edf9a5870c565a3589edcb0142ac0da114096f"
    hash3       = "e242e6c0ef360be00cd94f9bef2a3110481cea72bcad64bfbf232e1e9e9f8415"
    hash4       = "d4f0d1328060a87606ca6379182538690914ea1c94e0227455e79d3e631d8c0f"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* a  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* a  */;};" fullword ascii
    $s3 = "dot1 /* a  */= true;/* a  */" fullword ascii
    $s4 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* a  */, A8name /* a  *" ascii
    $s5 = "newtonsCradle1 /* a  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}