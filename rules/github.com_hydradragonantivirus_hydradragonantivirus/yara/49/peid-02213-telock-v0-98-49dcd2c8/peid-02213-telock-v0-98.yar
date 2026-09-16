rule PEiD_02213_tElock_v0_98_ {
  meta:
    description = "[tElock v0.98]"
    ep_only     = "true"

  strings:
    $a = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E }

  condition:
    $a
}