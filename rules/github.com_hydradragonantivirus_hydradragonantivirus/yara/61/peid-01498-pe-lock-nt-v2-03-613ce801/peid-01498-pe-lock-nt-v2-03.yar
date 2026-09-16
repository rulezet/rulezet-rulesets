rule PEiD_01498_PE_Lock_NT_v2_03_ {
  meta:
    description = "[PE Lock NT v2.03]"
    ep_only     = "true"

  strings:
    $a = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01 }

  condition:
    $a
}