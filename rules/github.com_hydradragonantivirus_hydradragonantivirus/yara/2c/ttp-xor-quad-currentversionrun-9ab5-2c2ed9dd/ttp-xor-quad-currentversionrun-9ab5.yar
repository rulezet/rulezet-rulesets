rule TTP_XOR_QUAD_CurrentVersionRun_9ab5 {
  strings:
    $key_9ab5 = { c9 da [2] ed d4 [2] c6 f8 [2] e8 da [2] fc c1 [2] f3 db [2] ed c6 [2] ef c7 [2] f4 c1 [2] e8 c6 [2] f4 e9 }

  condition:
    any of them
}