rule PEiD_01921_RCryptor_v1_3___v1_4_____Vaska_ {
  meta:
    description = "[RCryptor v1.3 / v1.4 --> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 }

  condition:
    $a
}