rule TTP_XOR_QUAD_CurrentVersionRun_3c85 {
  strings:
    $key_3c85 = { 6f ea [2] 4b e4 [2] 60 c8 [2] 4e ea [2] 5a f1 [2] 55 eb [2] 4b f6 [2] 49 f7 [2] 52 f1 [2] 4e f6 [2] 52 d9 }

  condition:
    any of them
}