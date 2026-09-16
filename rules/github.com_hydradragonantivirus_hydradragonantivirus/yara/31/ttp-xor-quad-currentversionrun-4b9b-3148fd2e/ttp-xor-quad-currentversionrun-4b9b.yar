rule TTP_XOR_QUAD_CurrentVersionRun_4b9b {
  strings:
    $key_4b9b = { 18 f4 [2] 3c fa [2] 17 d6 [2] 39 f4 [2] 2d ef [2] 22 f5 [2] 3c e8 [2] 3e e9 [2] 25 ef [2] 39 e8 [2] 25 c7 }

  condition:
    any of them
}