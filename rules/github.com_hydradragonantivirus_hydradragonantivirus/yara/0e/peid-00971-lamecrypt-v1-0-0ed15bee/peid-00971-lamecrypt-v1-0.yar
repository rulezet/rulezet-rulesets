rule PEiD_00971_LameCrypt_v1_0_ {
  meta:
    description = "[LameCrypt v1.0]"
    ep_only     = "true"

  strings:
    $a = { 60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }

  condition:
    $a
}