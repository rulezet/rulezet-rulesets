rule _20160518_84c396e3d4baee8db2df56a1a4cd37a5_20160519_3ebc7fe1dcdc_1311 {
  meta:
    description = "datamaliciousorder - from files 20160518_84c396e3d4baee8db2df56a1a4cd37a5.js, 20160519_3ebc7fe1dcdc9b30f5e1a41a33c8d024.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cc2533e128f4e06851b1b8ae3331f33594e48077251dae1853ad925d792986d"
    hash2       = "882a94e597019fe75bfaa3173e5478985ca0d17b10223ad245c0b7e632c6f997"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* s  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* s  */, A8name /* s  *" ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* s  */;};" fullword ascii
    $s4 = "newtonsCradle1 /* s  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "dot1 /* s  */= true;/* s  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}