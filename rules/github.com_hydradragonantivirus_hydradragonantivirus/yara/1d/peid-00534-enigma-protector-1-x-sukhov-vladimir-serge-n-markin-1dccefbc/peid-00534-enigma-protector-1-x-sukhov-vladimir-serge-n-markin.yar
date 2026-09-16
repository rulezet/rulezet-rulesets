rule PEiD_00534_Enigma_Protector_1_X____Sukhov_Vladimir___Serge_N__Markin_ {
  meta:
    description = "[Enigma Protector 1.X -> Sukhov Vladimir & Serge N. Markin]"
    ep_only     = "true"

  strings:
    $a = { 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4C 6F 61 }

  condition:
    $a
}