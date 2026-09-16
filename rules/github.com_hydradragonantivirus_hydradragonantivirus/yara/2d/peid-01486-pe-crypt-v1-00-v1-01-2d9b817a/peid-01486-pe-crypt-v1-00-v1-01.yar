rule PEiD_01486_PE_Crypt_v1_00_v1_01_ {
  meta:
    description = "[PE Crypt v1.00/v1.01]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

  condition:
    $a
}