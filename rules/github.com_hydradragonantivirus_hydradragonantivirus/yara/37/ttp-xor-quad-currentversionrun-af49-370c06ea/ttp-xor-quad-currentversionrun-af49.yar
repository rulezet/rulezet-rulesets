rule TTP_XOR_QUAD_CurrentVersionRun_af49 {
  strings:
    $key_af49 = { fc 26 [2] d8 28 [2] f3 04 [2] dd 26 [2] c9 3d [2] c6 27 [2] d8 3a [2] da 3b [2] c1 3d [2] dd 3a [2] c1 15 }

  condition:
    any of them
}