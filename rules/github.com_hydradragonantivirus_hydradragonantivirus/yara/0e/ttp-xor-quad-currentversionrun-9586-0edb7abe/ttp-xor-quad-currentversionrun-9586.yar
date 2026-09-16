rule TTP_XOR_QUAD_CurrentVersionRun_9586 {
  strings:
    $key_9586 = { c6 e9 [2] e2 e7 [2] c9 cb [2] e7 e9 [2] f3 f2 [2] fc e8 [2] e2 f5 [2] e0 f4 [2] fb f2 [2] e7 f5 [2] fb da }

  condition:
    any of them
}