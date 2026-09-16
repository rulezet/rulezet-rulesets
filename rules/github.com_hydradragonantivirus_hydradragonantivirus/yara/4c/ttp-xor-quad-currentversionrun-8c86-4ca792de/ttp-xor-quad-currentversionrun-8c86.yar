rule TTP_XOR_QUAD_CurrentVersionRun_8c86 {
  strings:
    $key_8c86 = { df e9 [2] fb e7 [2] d0 cb [2] fe e9 [2] ea f2 [2] e5 e8 [2] fb f5 [2] f9 f4 [2] e2 f2 [2] fe f5 [2] e2 da }

  condition:
    any of them
}