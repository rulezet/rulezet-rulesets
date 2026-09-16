rule TTP_XOR_QUAD_CurrentVersionRun_95fa {
  strings:
    $key_95fa = { c6 95 [2] e2 9b [2] c9 b7 [2] e7 95 [2] f3 8e [2] fc 94 [2] e2 89 [2] e0 88 [2] fb 8e [2] e7 89 [2] fb a6 }

  condition:
    any of them
}