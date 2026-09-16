rule TTP_XOR_QUAD_CurrentVersionRun_af09 {
  strings:
    $key_af09 = { fc 66 [2] d8 68 [2] f3 44 [2] dd 66 [2] c9 7d [2] c6 67 [2] d8 7a [2] da 7b [2] c1 7d [2] dd 7a [2] c1 55 }

  condition:
    any of them
}