rule PEiD_02208_tElock_v0_90_ {
  meta:
    description = "[tElock v0.90]"
    ep_only     = "true"

  strings:
    $a = { ?? ?? E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }

  condition:
    $a
}