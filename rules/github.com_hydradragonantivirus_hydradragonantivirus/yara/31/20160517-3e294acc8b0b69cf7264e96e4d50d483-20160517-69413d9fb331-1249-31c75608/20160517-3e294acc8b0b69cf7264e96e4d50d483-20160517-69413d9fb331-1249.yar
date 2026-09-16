rule _20160517_3e294acc8b0b69cf7264e96e4d50d483_20160517_69413d9fb331_1249 {
  meta:
    description = "datamaliciousorder - from files 20160517_3e294acc8b0b69cf7264e96e4d50d483.js, 20160517_69413d9fb331c9f8f9649d46c851935d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74512507cfbbfbb82dbb5a04bdc0c0a986cb194f806383589e1e786477c2139f"
    hash2       = "e100898e979155cfe276f01de8b09f146fa76fbb3078a9d7e7d1975730552325"

  strings:
    $s1 = "function Scott /* N  */(accinp0 /* N  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* N  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* N  */ = (123, Turkey); return devel0 /* N  */;};" fullword ascii
    $s4 = "DENMARK1 /* N  */= true;/* N  */" fullword ascii
    $s5 = "function Scott /* N  */(accinp0 /* N  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "place = /* N  */(/* N  */\"noitisop\").split(''/* N  */).reverse(/* N  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}