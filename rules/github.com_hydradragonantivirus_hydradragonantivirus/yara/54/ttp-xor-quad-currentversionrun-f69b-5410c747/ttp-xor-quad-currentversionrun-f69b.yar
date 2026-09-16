rule TTP_XOR_QUAD_CurrentVersionRun_f69b {
  strings:
    $key_f69b = { a5 f4 [2] 81 fa [2] aa d6 [2] 84 f4 [2] 90 ef [2] 9f f5 [2] 81 e8 [2] 83 e9 [2] 98 ef [2] 84 e8 [2] 98 c7 }

  condition:
    any of them
}