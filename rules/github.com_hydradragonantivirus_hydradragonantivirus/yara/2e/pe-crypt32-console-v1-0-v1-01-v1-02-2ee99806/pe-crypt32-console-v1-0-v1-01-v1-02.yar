import "pe"
rule PE_Crypt32__Console_v1_0__v1_01__v1_02_ {
  strings:
    $a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

  condition:
    $a0 at pe.entry_point
}