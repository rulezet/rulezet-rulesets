rule TTP_XOR_QUAD_CurrentVersionRun_952b {
  strings:
    $key_952b = { c6 44 [2] e2 4a [2] c9 66 [2] e7 44 [2] f3 5f [2] fc 45 [2] e2 58 [2] e0 59 [2] fb 5f [2] e7 58 [2] fb 77 }

  condition:
    any of them
}