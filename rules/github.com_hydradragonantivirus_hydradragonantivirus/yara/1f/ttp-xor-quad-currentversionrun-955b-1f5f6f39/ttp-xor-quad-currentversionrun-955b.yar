rule TTP_XOR_QUAD_CurrentVersionRun_955b {
  strings:
    $key_955b = { c6 34 [2] e2 3a [2] c9 16 [2] e7 34 [2] f3 2f [2] fc 35 [2] e2 28 [2] e0 29 [2] fb 2f [2] e7 28 [2] fb 07 }

  condition:
    any of them
}