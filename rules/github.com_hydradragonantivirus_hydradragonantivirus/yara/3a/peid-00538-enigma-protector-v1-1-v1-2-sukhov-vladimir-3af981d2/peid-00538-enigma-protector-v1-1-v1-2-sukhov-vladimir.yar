rule PEiD_00538_ENIGMA_Protector_V1_1_V1_2____Sukhov_Vladimir_ {
  meta:
    description = "[ENIGMA Protector V1.1-V1.2 -> Sukhov Vladimir]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 83 ED 06 81 }

  condition:
    $a
}