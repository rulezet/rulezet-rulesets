rule TTP_XOR_QUAD_CurrentVersionRun_2c85 {
  strings:
    $key_2c85 = { 7f ea [2] 5b e4 [2] 70 c8 [2] 5e ea [2] 4a f1 [2] 45 eb [2] 5b f6 [2] 59 f7 [2] 42 f1 [2] 5e f6 [2] 42 d9 }

  condition:
    any of them
}