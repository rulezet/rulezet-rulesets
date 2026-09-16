rule TTP_XOR_QUAD_CurrentVersionRun_6c85 {
  strings:
    $key_6c85 = { 3f ea [2] 1b e4 [2] 30 c8 [2] 1e ea [2] 0a f1 [2] 05 eb [2] 1b f6 [2] 19 f7 [2] 02 f1 [2] 1e f6 [2] 02 d9 }

  condition:
    any of them
}