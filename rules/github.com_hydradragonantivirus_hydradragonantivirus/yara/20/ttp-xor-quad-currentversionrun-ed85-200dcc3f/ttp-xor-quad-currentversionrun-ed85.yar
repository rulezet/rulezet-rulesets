rule TTP_XOR_QUAD_CurrentVersionRun_ed85 {
  strings:
    $key_ed85 = { be ea [2] 9a e4 [2] b1 c8 [2] 9f ea [2] 8b f1 [2] 84 eb [2] 9a f6 [2] 98 f7 [2] 83 f1 [2] 9f f6 [2] 83 d9 }

  condition:
    any of them
}