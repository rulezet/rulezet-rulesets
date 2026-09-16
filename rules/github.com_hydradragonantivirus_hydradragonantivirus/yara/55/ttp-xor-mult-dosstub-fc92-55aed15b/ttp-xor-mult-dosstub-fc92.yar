rule TTP_XOR_MULT_DOSStub_fc92 {
  strings:
    $key_fc92 = { a8 fa [2] dc e2 [2] 9b e0 [2] dc f1 [2] 92 fd [2] 9e f7 [2] 89 fc [2] 92 b2 [2] af }

  condition:
    any of them
}