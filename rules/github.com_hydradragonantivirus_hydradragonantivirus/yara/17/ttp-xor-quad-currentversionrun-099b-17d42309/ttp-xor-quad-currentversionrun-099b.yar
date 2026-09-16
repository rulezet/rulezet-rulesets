rule TTP_XOR_QUAD_CurrentVersionRun_099b {
  strings:
    $key_099b = { 5a f4 [2] 7e fa [2] 55 d6 [2] 7b f4 [2] 6f ef [2] 60 f5 [2] 7e e8 [2] 7c e9 [2] 67 ef [2] 7b e8 [2] 67 c7 }

  condition:
    any of them
}