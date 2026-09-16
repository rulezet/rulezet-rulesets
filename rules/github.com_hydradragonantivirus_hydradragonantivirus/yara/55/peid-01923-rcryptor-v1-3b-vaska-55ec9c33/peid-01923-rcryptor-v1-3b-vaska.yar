rule PEiD_01923_RCryptor_v1_3b_____Vaska_ {
  meta:
    description = "[RCryptor v1.3b --> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 }

  condition:
    $a
}