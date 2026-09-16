rule TTP_XOR_QUAD_CurrentVersionRun_0c85 {
  strings:
    $key_0c85 = { 5f ea [2] 7b e4 [2] 50 c8 [2] 7e ea [2] 6a f1 [2] 65 eb [2] 7b f6 [2] 79 f7 [2] 62 f1 [2] 7e f6 [2] 62 d9 }

  condition:
    any of them
}