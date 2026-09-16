rule PEiD_01899_PUNiSHER_V1_5_Demo____FEUERRADER_ {
  meta:
    description = "[PUNiSHER V1.5 Demo -> FEUERRADER]"
    ep_only     = "true"

  strings:
    $a = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 }

  condition:
    $a
}