rule PEiD_02192_tElock_0_99____tE__ {
  meta:
    description = "[tElock 0.99 -> tE!]"
    ep_only     = "true"

  strings:
    $a = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 }

  condition:
    $a
}