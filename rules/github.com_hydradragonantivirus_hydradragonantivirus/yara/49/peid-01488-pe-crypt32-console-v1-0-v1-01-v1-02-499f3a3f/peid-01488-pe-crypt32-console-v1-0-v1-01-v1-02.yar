rule PEiD_01488_PE_Crypt32__Console_v1_0__v1_01__v1_02__ {
  meta:
    description = "[PE Crypt32 (Console v1.0, v1.01, v1.02)]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

  condition:
    $a
}