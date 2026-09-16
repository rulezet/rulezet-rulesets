rule PEiD_00457_DCrypt_Private_0_9b____drmist_ {
  meta:
    description = "[DCrypt Private 0.9b -> drmist]"
    ep_only     = "true"

  strings:
    $a = { B9 ?? ?? ?? 00 E8 00 00 00 00 58 68 ?? ?? ?? 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3 }

  condition:
    $a
}