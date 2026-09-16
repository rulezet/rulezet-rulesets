rule TTP_XOR_QUAD_CurrentVersionRun_50aa {
  strings:
    $key_50aa = { 03 c5 [2] 27 cb [2] 0c e7 [2] 22 c5 [2] 36 de [2] 39 c4 [2] 27 d9 [2] 25 d8 [2] 3e de [2] 22 d9 [2] 3e f6 }

  condition:
    any of them
}