rule TTP_XOR_QUAD_CurrentVersionRun_169b {
  strings:
    $key_169b = { 45 f4 [2] 61 fa [2] 4a d6 [2] 64 f4 [2] 70 ef [2] 7f f5 [2] 61 e8 [2] 63 e9 [2] 78 ef [2] 64 e8 [2] 78 c7 }

  condition:
    any of them
}