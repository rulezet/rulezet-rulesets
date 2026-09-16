rule TTP_XOR_QUAD_CurrentVersionRun_af62 {
  strings:
    $key_af62 = { fc 0d [2] d8 03 [2] f3 2f [2] dd 0d [2] c9 16 [2] c6 0c [2] d8 11 [2] da 10 [2] c1 16 [2] dd 11 [2] c1 3e }

  condition:
    any of them
}