rule PEiD_01917_RCryptor_2_0____Vaska_ {
  meta:
    description = "[RCryptor 2.0 -> Vaska]"
    ep_only     = "true"

  strings:
    $a = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF }

  condition:
    $a
}