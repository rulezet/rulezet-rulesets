rule TTP_XOR_QUAD_CurrentVersionRun_2b9b {
  strings:
    $key_2b9b = { 78 f4 [2] 5c fa [2] 77 d6 [2] 59 f4 [2] 4d ef [2] 42 f5 [2] 5c e8 [2] 5e e9 [2] 45 ef [2] 59 e8 [2] 45 c7 }

  condition:
    any of them
}