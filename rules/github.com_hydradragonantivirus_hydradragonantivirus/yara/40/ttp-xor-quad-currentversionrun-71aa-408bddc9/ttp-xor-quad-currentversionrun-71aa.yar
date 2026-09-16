rule TTP_XOR_QUAD_CurrentVersionRun_71aa {
  strings:
    $key_71aa = { 22 c5 [2] 06 cb [2] 2d e7 [2] 03 c5 [2] 17 de [2] 18 c4 [2] 06 d9 [2] 04 d8 [2] 1f de [2] 03 d9 [2] 1f f6 }

  condition:
    any of them
}