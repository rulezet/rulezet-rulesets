rule PEiD_01521_PE_Crypt_1_02_ {
  meta:
    description = "[PE-Crypt 1.02]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 }

  condition:
    $a
}