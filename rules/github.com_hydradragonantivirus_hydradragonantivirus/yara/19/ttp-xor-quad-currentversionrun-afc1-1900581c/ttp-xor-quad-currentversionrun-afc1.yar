rule TTP_XOR_QUAD_CurrentVersionRun_afc1 {
  strings:
    $key_afc1 = { fc ae [2] d8 a0 [2] f3 8c [2] dd ae [2] c9 b5 [2] c6 af [2] d8 b2 [2] da b3 [2] c1 b5 [2] dd b2 [2] c1 9d }

  condition:
    any of them
}