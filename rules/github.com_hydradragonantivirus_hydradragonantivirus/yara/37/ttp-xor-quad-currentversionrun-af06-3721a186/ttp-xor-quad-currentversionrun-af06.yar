rule TTP_XOR_QUAD_CurrentVersionRun_af06 {
  strings:
    $key_af06 = { fc 69 [2] d8 67 [2] f3 4b [2] dd 69 [2] c9 72 [2] c6 68 [2] d8 75 [2] da 74 [2] c1 72 [2] dd 75 [2] c1 5a }

  condition:
    any of them
}