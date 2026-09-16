rule PEiD_02204_tElock_v0_71b7_ {
  meta:
    description = "[tElock v0.71b7]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 48 11 00 00 C3 83 }

  condition:
    $a
}