rule TTP_XOR_QUAD_CurrentVersionRun_afc3 {
  strings:
    $key_afc3 = { fc ac [2] d8 a2 [2] f3 8e [2] dd ac [2] c9 b7 [2] c6 ad [2] d8 b0 [2] da b1 [2] c1 b7 [2] dd b0 [2] c1 9f }

  condition:
    any of them
}