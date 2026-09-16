rule PEiD_01496_PE_Lock_NT_v2_01_ {
  meta:
    description = "[PE Lock NT v2.01]"
    ep_only     = "true"

  strings:
    $a = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }

  condition:
    $a
}