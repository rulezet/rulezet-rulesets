rule PEiD_01936_RCryptor_v1_6x____Vaska_ {
  meta:
    description = "[RCryptor v1.6x -> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 ?? ?? ?? ?? C3 }

  condition:
    $a
}