rule _20160518_8c707844e8e95c4700f81375ec48c957_20160518_d65d54637152_1313 {
  meta:
    description = "datamaliciousorder - from files 20160518_8c707844e8e95c4700f81375ec48c957.js, 20160518_d65d54637152783d68e8a22407d35aaf.js, 20160519_ef550f6d1b14c8722cced385ffcf641b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e1945ce6711aded53e680d8bcc1c26ff32ef00879539b3029bbde8d52a8b2bd"
    hash2       = "09dad1b73399d584115f8d4b7138cb2f48df21ab21cff59f4840253c7ca8226f"
    hash3       = "6f7bce17f171ac6579a768987d2934c284a7d7faca54b2061b5b3fa5bf6aaf19"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* P  */, dingy, (true, false));" fullword ascii
    $s2 = "newtonsCradle1 /* P  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s3 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* P  */, A8name /* P  *" ascii
    $s4 = "function sDiv2(){return newtonsCradle0 /* P  */;};" fullword ascii
    $s5 = "dot1 /* P  */= true;/* P  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}