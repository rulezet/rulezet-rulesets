rule TTP_XOR_QUAD_CurrentVersionRun_95fb {
  strings:
    $key_95fb = { c6 94 [2] e2 9a [2] c9 b6 [2] e7 94 [2] f3 8f [2] fc 95 [2] e2 88 [2] e0 89 [2] fb 8f [2] e7 88 [2] fb a7 }

  condition:
    any of them
}