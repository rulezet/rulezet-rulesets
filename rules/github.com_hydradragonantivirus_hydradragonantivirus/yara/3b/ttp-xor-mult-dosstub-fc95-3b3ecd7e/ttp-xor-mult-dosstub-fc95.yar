rule TTP_XOR_MULT_DOSStub_fc95 {
  strings:
    $key_fc95 = { a8 fd [2] dc e5 [2] 9b e7 [2] dc f6 [2] 92 fa [2] 9e f0 [2] 89 fb [2] 92 b5 [2] af }

  condition:
    any of them
}