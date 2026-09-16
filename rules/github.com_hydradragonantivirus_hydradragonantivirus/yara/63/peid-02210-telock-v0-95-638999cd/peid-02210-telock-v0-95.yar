rule PEiD_02210_tElock_v0_95_ {
  meta:
    description = "[tElock v0.95]"
    ep_only     = "true"

  strings:
    $a = { E9 D5 E4 FF FF 00 }

  condition:
    $a
}