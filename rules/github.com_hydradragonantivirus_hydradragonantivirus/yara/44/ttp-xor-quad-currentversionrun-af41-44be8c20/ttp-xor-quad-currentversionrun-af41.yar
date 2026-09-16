rule TTP_XOR_QUAD_CurrentVersionRun_af41 {
  strings:
    $key_af41 = { fc 2e [2] d8 20 [2] f3 0c [2] dd 2e [2] c9 35 [2] c6 2f [2] d8 32 [2] da 33 [2] c1 35 [2] dd 32 [2] c1 1d }

  condition:
    any of them
}