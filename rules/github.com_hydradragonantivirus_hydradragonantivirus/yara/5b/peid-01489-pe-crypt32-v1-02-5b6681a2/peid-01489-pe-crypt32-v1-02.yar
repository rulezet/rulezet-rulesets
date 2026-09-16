rule PEiD_01489_PE_Crypt32_v1_02_ {
  meta:
    description = "[PE Crypt32 v1.02]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 5B 83 ?? ?? EB ?? 52 4E 44 21 }

  condition:
    $a
}