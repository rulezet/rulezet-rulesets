rule _20160518_6b417be3a102295bab47c7c43fa055c0_20160518_ebc06d8e3c06_1304 {
  meta:
    description = "datamaliciousorder - from files 20160518_6b417be3a102295bab47c7c43fa055c0.js, 20160518_ebc06d8e3c0696a26f0ab801a8f24a43.js, 20160519_fd1ac2dcc5c415b286945b2bdb01ee41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e47b1f74f19588b043981a2da7840c020e246b65e7b3faa279cfd38822e9123"
    hash2       = "8e3004eb0f8efe7b04c6c7313e8a5936f04cad6c18be527fca1e9dbda1044a3f"
    hash3       = "9fb35998ec7524e5e456ca259fba6d8f7b90a9dc14858bab8d261282797efeba"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* C  */, dingy, (true, false));" fullword ascii
    $s2 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* C  */, A8name /* C  *" ascii
    $s3 = "function sDiv2(){return newtonsCradle0 /* C  */;};" fullword ascii
    $s4 = "newtonsCradle1 /* C  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "dot1 /* C  */= true;/* C  */" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}