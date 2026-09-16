rule TTP_XOR_QUAD_CurrentVersionRun_957b {
  strings:
    $key_957b = { c6 14 [2] e2 1a [2] c9 36 [2] e7 14 [2] f3 0f [2] fc 15 [2] e2 08 [2] e0 09 [2] fb 0f [2] e7 08 [2] fb 27 }

  condition:
    any of them
}