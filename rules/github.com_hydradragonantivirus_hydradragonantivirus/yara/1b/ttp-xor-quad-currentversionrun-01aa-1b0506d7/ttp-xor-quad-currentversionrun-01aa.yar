rule TTP_XOR_QUAD_CurrentVersionRun_01aa {
  strings:
    $key_01aa = { 52 c5 [2] 76 cb [2] 5d e7 [2] 73 c5 [2] 67 de [2] 68 c4 [2] 76 d9 [2] 74 d8 [2] 6f de [2] 73 d9 [2] 6f f6 }

  condition:
    any of them
}