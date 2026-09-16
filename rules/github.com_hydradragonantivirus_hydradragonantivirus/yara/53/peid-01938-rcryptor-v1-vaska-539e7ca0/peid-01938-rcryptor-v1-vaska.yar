rule PEiD_01938_RCryptor_v1_______Vaska_ {
  meta:
    description = "[RCryptor v1.?? -> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }

  condition:
    $a
}