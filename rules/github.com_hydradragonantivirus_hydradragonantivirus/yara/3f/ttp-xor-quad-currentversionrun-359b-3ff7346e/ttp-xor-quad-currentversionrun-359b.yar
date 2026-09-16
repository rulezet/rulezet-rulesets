rule TTP_XOR_QUAD_CurrentVersionRun_359b {
  strings:
    $key_359b = { 66 f4 [2] 42 fa [2] 69 d6 [2] 47 f4 [2] 53 ef [2] 5c f5 [2] 42 e8 [2] 40 e9 [2] 5b ef [2] 47 e8 [2] 5b c7 }

  condition:
    any of them
}