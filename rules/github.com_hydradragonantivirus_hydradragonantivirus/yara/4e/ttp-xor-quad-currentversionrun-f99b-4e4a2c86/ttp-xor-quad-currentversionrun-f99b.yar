rule TTP_XOR_QUAD_CurrentVersionRun_f99b {
  strings:
    $key_f99b = { aa f4 [2] 8e fa [2] a5 d6 [2] 8b f4 [2] 9f ef [2] 90 f5 [2] 8e e8 [2] 8c e9 [2] 97 ef [2] 8b e8 [2] 97 c7 }

  condition:
    any of them
}