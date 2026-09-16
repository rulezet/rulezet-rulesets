rule TTP_XOR_QUAD_CurrentVersionRun_af25 {
  strings:
    $key_af25 = { fc 4a [2] d8 44 [2] f3 68 [2] dd 4a [2] c9 51 [2] c6 4b [2] d8 56 [2] da 57 [2] c1 51 [2] dd 56 [2] c1 79 }

  condition:
    any of them
}