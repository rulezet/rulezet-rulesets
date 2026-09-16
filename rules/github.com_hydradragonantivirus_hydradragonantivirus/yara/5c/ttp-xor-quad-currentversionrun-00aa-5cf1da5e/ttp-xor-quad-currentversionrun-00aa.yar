rule TTP_XOR_QUAD_CurrentVersionRun_00aa {
  strings:
    $key_00aa = { 53 c5 [2] 77 cb [2] 5c e7 [2] 72 c5 [2] 66 de [2] 69 c4 [2] 77 d9 [2] 75 d8 [2] 6e de [2] 72 d9 [2] 6e f6 }

  condition:
    any of them
}