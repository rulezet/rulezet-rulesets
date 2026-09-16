rule TTP_XOR_QUAD_CurrentVersionRun_ed9b {
  strings:
    $key_ed9b = { be f4 [2] 9a fa [2] b1 d6 [2] 9f f4 [2] 8b ef [2] 84 f5 [2] 9a e8 [2] 98 e9 [2] 83 ef [2] 9f e8 [2] 83 c7 }

  condition:
    any of them
}