rule _20160518_7730218a280e78e4e884627bf11c9c44_20160518_ec7682e84d54_1309 {
  meta:
    description = "datamaliciousorder - from files 20160518_7730218a280e78e4e884627bf11c9c44.js, 20160518_ec7682e84d5491c309529d7686929ea4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "445fb69ccde27c6b76df57517747d00586243316d9d301e5bceed89f78d343e9"
    hash2       = "3268233888dafb80d1f1789dbdc1dcdfcf5e0f958c6d58928c9b8fa4a2ca3359"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* J  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* J  */, A8name /* J  *" ascii
    $s3 = "newtonsCradle1 /* J  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* J  */;};" fullword ascii
    $s5 = "dot1 /* J  */= true;/* J  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}