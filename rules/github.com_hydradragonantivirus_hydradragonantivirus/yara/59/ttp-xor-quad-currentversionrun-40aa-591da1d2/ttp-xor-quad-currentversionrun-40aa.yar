rule TTP_XOR_QUAD_CurrentVersionRun_40aa {
  strings:
    $key_40aa = { 13 c5 [2] 37 cb [2] 1c e7 [2] 32 c5 [2] 26 de [2] 29 c4 [2] 37 d9 [2] 35 d8 [2] 2e de [2] 32 d9 [2] 2e f6 }

  condition:
    any of them
}