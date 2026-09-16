rule TTP_XOR_QUAD_CurrentVersionRun_4d85 {
  strings:
    $key_4d85 = { 1e ea [2] 3a e4 [2] 11 c8 [2] 3f ea [2] 2b f1 [2] 24 eb [2] 3a f6 [2] 38 f7 [2] 23 f1 [2] 3f f6 [2] 23 d9 }

  condition:
    any of them
}