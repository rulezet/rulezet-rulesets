rule TTP_XOR_QUAD_CurrentVersionRun_e59b {
  strings:
    $key_e59b = { b6 f4 [2] 92 fa [2] b9 d6 [2] 97 f4 [2] 83 ef [2] 8c f5 [2] 92 e8 [2] 90 e9 [2] 8b ef [2] 97 e8 [2] 8b c7 }

  condition:
    any of them
}