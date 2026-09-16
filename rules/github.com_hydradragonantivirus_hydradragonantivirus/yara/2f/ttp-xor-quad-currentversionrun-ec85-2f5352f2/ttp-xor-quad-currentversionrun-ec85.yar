rule TTP_XOR_QUAD_CurrentVersionRun_ec85 {
  strings:
    $key_ec85 = { bf ea [2] 9b e4 [2] b0 c8 [2] 9e ea [2] 8a f1 [2] 85 eb [2] 9b f6 [2] 99 f7 [2] 82 f1 [2] 9e f6 [2] 82 d9 }

  condition:
    any of them
}