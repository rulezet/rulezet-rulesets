rule TTP_XOR_QUAD_CurrentVersionRun_9ab8 {
  strings:
    $key_9ab8 = { c9 d7 [2] ed d9 [2] c6 f5 [2] e8 d7 [2] fc cc [2] f3 d6 [2] ed cb [2] ef ca [2] f4 cc [2] e8 cb [2] f4 e4 }

  condition:
    any of them
}