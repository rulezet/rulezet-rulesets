rule PEiD_01528_PE_PROTECT_0_9_ {
  meta:
    description = "[PE-PROTECT 0.9]"
    ep_only     = "true"

  strings:
    $a = { E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

  condition:
    $a
}