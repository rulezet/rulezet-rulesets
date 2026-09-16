rule TTP_XOR_QUAD_CurrentVersionRun_7d85 {
  strings:
    $key_7d85 = { 2e ea [2] 0a e4 [2] 21 c8 [2] 0f ea [2] 1b f1 [2] 14 eb [2] 0a f6 [2] 08 f7 [2] 13 f1 [2] 0f f6 [2] 13 d9 }

  condition:
    any of them
}