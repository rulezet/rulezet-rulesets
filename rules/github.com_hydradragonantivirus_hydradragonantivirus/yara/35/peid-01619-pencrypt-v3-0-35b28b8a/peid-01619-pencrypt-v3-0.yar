rule PEiD_01619_PEncrypt_v3_0_ {
  meta:
    description = "[PEncrypt v3.0]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB ?? ?? ?? ?? AD 33 C3 E2 FA }

  condition:
    $a
}