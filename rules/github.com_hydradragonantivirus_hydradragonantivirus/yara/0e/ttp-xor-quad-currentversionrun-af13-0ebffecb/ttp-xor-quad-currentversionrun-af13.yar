rule TTP_XOR_QUAD_CurrentVersionRun_af13 {
  strings:
    $key_af13 = { fc 7c [2] d8 72 [2] f3 5e [2] dd 7c [2] c9 67 [2] c6 7d [2] d8 60 [2] da 61 [2] c1 67 [2] dd 60 [2] c1 4f }

  condition:
    any of them
}