rule PEiD_01920_RCryptor_v1_1____Vaska_ {
  meta:
    description = "[RCryptor v1.1 -> Vaska]"
    ep_only     = "false"

  strings:
    $a = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3 }

  condition:
    $a
}