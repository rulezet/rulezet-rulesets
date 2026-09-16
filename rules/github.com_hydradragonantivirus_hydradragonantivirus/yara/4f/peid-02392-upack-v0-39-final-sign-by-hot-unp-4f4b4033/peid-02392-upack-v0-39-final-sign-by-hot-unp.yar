rule PEiD_02392_Upack_v0_39_final____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.39 final -> Sign by hot_UNP]"
    ep_only     = "false"

  strings:
    $a = { FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF }

  condition:
    $a
}