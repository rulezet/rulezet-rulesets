rule TTP_XOR_QUAD_CurrentVersionRun_afc0 {
  strings:
    $key_afc0 = { fc af [2] d8 a1 [2] f3 8d [2] dd af [2] c9 b4 [2] c6 ae [2] d8 b3 [2] da b2 [2] c1 b4 [2] dd b3 [2] c1 9c }

  condition:
    any of them
}