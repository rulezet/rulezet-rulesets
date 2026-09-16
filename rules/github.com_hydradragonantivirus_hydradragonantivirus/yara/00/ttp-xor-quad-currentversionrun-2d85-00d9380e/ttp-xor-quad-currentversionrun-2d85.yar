rule TTP_XOR_QUAD_CurrentVersionRun_2d85 {
  strings:
    $key_2d85 = { 7e ea [2] 5a e4 [2] 71 c8 [2] 5f ea [2] 4b f1 [2] 44 eb [2] 5a f6 [2] 58 f7 [2] 43 f1 [2] 5f f6 [2] 43 d9 }

  condition:
    any of them
}