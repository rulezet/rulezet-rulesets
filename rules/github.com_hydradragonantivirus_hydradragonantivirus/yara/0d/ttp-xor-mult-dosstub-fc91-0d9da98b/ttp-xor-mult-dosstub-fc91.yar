rule TTP_XOR_MULT_DOSStub_fc91 {
  strings:
    $key_fc91 = { a8 f9 [2] dc e1 [2] 9b e3 [2] dc f2 [2] 92 fe [2] 9e f4 [2] 89 ff [2] 92 b1 [2] af }

  condition:
    any of them
}