rule TTP_XOR_QUAD_CurrentVersionRun_95c7 {
  strings:
    $key_95c7 = { c6 a8 [2] e2 a6 [2] c9 8a [2] e7 a8 [2] f3 b3 [2] fc a9 [2] e2 b4 [2] e0 b5 [2] fb b3 [2] e7 b4 [2] fb 9b }

  condition:
    any of them
}