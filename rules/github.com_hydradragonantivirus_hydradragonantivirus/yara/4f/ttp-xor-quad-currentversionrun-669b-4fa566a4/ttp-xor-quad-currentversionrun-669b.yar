rule TTP_XOR_QUAD_CurrentVersionRun_669b {
  strings:
    $key_669b = { 35 f4 [2] 11 fa [2] 3a d6 [2] 14 f4 [2] 00 ef [2] 0f f5 [2] 11 e8 [2] 13 e9 [2] 08 ef [2] 14 e8 [2] 08 c7 }

  condition:
    any of them
}