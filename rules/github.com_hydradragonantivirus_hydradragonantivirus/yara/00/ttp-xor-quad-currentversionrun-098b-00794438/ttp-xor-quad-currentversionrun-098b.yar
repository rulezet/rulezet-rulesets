rule TTP_XOR_QUAD_CurrentVersionRun_098b {
  strings:
    $key_098b = { 5a e4 [2] 7e ea [2] 55 c6 [2] 7b e4 [2] 6f ff [2] 60 e5 [2] 7e f8 [2] 7c f9 [2] 67 ff [2] 7b f8 [2] 67 d7 }

  condition:
    any of them
}