rule TTP_XOR_QUAD_CurrentVersionRun_9a86 {
  strings:
    $key_9a86 = { c9 e9 [2] ed e7 [2] c6 cb [2] e8 e9 [2] fc f2 [2] f3 e8 [2] ed f5 [2] ef f4 [2] f4 f2 [2] e8 f5 [2] f4 da }

  condition:
    any of them
}