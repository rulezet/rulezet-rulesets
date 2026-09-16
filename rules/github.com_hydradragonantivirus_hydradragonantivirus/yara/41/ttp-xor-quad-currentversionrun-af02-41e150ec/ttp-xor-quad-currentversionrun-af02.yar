rule TTP_XOR_QUAD_CurrentVersionRun_af02 {
  strings:
    $key_af02 = { fc 6d [2] d8 63 [2] f3 4f [2] dd 6d [2] c9 76 [2] c6 6c [2] d8 71 [2] da 70 [2] c1 76 [2] dd 71 [2] c1 5e }

  condition:
    any of them
}