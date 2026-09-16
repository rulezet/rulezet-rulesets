rule TTP_XOR_QUAD_CurrentVersionRun_9ab3 {
  strings:
    $key_9ab3 = { c9 dc [2] ed d2 [2] c6 fe [2] e8 dc [2] fc c7 [2] f3 dd [2] ed c0 [2] ef c1 [2] f4 c7 [2] e8 c0 [2] f4 ef }

  condition:
    any of them
}