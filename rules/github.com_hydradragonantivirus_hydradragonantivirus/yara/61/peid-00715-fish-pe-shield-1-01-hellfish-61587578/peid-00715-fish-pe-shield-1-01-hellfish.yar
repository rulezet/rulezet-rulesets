rule PEiD_00715_Fish_PE_Shield_1_01____HellFish_ {
  meta:
    description = "[Fish PE Shield 1.01 -> HellFish]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 12 FE FF FF C3 90 09 00 00 00 2C 00 00 00 }

  condition:
    $a
}