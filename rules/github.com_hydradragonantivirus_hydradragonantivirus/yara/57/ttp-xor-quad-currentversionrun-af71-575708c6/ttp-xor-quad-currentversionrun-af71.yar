rule TTP_XOR_QUAD_CurrentVersionRun_af71 {
  strings:
    $key_af71 = { fc 1e [2] d8 10 [2] f3 3c [2] dd 1e [2] c9 05 [2] c6 1f [2] d8 02 [2] da 03 [2] c1 05 [2] dd 02 [2] c1 2d }

  condition:
    any of them
}