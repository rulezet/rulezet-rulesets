rule TTP_XOR_QUAD_CurrentVersionRun_649b {
  strings:
    $key_649b = { 37 f4 [2] 13 fa [2] 38 d6 [2] 16 f4 [2] 02 ef [2] 0d f5 [2] 13 e8 [2] 11 e9 [2] 0a ef [2] 16 e8 [2] 0a c7 }

  condition:
    any of them
}