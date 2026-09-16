rule TTP_XOR_QUAD_CurrentVersionRun_af51 {
  strings:
    $key_af51 = { fc 3e [2] d8 30 [2] f3 1c [2] dd 3e [2] c9 25 [2] c6 3f [2] d8 22 [2] da 23 [2] c1 25 [2] dd 22 [2] c1 0d }

  condition:
    any of them
}