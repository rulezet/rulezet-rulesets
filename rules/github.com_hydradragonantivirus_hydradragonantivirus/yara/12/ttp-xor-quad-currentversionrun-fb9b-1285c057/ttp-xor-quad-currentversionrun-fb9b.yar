rule TTP_XOR_QUAD_CurrentVersionRun_fb9b {
  strings:
    $key_fb9b = { a8 f4 [2] 8c fa [2] a7 d6 [2] 89 f4 [2] 9d ef [2] 92 f5 [2] 8c e8 [2] 8e e9 [2] 95 ef [2] 89 e8 [2] 95 c7 }

  condition:
    any of them
}