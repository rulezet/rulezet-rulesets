rule TTP_XOR_QUAD_CurrentVersionRun_9ac0 {
  strings:
    $key_9ac0 = { c9 af [2] ed a1 [2] c6 8d [2] e8 af [2] fc b4 [2] f3 ae [2] ed b3 [2] ef b2 [2] f4 b4 [2] e8 b3 [2] f4 9c }

  condition:
    any of them
}