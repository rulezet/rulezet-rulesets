rule TTP_XOR_MULT_DOSStub_fc90 {
  strings:
    $key_fc90 = { a8 f8 [2] dc e0 [2] 9b e2 [2] dc f3 [2] 92 ff [2] 9e f5 [2] 89 fe [2] 92 b0 [2] af }

  condition:
    any of them
}