rule TTP_XOR_QUAD_CurrentVersionRun_f98b {
  strings:
    $key_f98b = { aa e4 [2] 8e ea [2] a5 c6 [2] 8b e4 [2] 9f ff [2] 90 e5 [2] 8e f8 [2] 8c f9 [2] 97 ff [2] 8b f8 [2] 97 d7 }

  condition:
    any of them
}