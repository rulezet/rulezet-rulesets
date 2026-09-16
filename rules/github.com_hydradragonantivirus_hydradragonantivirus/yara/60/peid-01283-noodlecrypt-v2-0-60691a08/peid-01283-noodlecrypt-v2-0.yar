rule PEiD_01283_NoodleCrypt_v2_0_ {
  meta:
    description = "[NoodleCrypt v2.0]"
    ep_only     = "false"

  strings:
    $a = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 }

  condition:
    $a
}