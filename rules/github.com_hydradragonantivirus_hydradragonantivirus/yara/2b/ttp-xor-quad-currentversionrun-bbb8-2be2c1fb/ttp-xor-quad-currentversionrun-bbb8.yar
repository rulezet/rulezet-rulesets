rule TTP_XOR_QUAD_CurrentVersionRun_bbb8 {
  strings:
    $key_bbb8 = { e8 d7 [2] cc d9 [2] e7 f5 [2] c9 d7 [2] dd cc [2] d2 d6 [2] cc cb [2] ce ca [2] d5 cc [2] c9 cb [2] d5 e4 }

  condition:
    any of them
}