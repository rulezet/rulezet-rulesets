rule TTP_XOR_QUAD_CurrentVersionRun_049b {
  strings:
    $key_049b = { 57 f4 [2] 73 fa [2] 58 d6 [2] 76 f4 [2] 62 ef [2] 6d f5 [2] 73 e8 [2] 71 e9 [2] 6a ef [2] 76 e8 [2] 6a c7 }

  condition:
    any of them
}