rule TTP_XOR_QUAD_CurrentVersionRun_f19b {
  strings:
    $key_f19b = { a2 f4 [2] 86 fa [2] ad d6 [2] 83 f4 [2] 97 ef [2] 98 f5 [2] 86 e8 [2] 84 e9 [2] 9f ef [2] 83 e8 [2] 9f c7 }

  condition:
    any of them
}