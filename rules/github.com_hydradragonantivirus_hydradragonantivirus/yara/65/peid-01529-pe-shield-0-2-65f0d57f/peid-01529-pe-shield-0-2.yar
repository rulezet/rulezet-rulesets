rule PEiD_01529_PE_SHiELD_0_2_ {
  meta:
    description = "[PE-SHiELD 0.2]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

  condition:
    $a
}