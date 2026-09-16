rule TTP_XOR_QUAD_CurrentVersionRun_698b {
  strings:
    $key_698b = { 3a e4 [2] 1e ea [2] 35 c6 [2] 1b e4 [2] 0f ff [2] 00 e5 [2] 1e f8 [2] 1c f9 [2] 07 ff [2] 1b f8 [2] 07 d7 }

  condition:
    any of them
}