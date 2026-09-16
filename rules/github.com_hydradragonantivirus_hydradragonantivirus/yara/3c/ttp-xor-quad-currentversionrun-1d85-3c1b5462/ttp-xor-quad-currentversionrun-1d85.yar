rule TTP_XOR_QUAD_CurrentVersionRun_1d85 {
  strings:
    $key_1d85 = { 4e ea [2] 6a e4 [2] 41 c8 [2] 6f ea [2] 7b f1 [2] 74 eb [2] 6a f6 [2] 68 f7 [2] 73 f1 [2] 6f f6 [2] 73 d9 }

  condition:
    any of them
}