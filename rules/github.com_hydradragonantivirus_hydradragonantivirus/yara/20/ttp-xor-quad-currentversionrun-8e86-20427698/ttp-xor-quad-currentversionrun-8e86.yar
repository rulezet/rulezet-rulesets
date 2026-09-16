rule TTP_XOR_QUAD_CurrentVersionRun_8e86 {
  strings:
    $key_8e86 = { dd e9 [2] f9 e7 [2] d2 cb [2] fc e9 [2] e8 f2 [2] e7 e8 [2] f9 f5 [2] fb f4 [2] e0 f2 [2] fc f5 [2] e0 da }

  condition:
    any of them
}