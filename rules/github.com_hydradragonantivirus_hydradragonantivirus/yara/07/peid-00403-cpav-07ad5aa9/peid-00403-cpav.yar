rule PEiD_00403_CPAV_ {
  meta:
    description = "[CPAV]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 4D 5A B1 01 93 01 00 00 02 }

  condition:
    $a
}