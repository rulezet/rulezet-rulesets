rule TTP_XOR_MULT_DOSStub_fc93 {
  strings:
    $key_fc93 = { a8 fb [2] dc e3 [2] 9b e1 [2] dc f0 [2] 92 fc [2] 9e f6 [2] 89 fd [2] 92 b3 [2] af }

  condition:
    any of them
}