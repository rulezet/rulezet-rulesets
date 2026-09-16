rule TTP_XOR_MULT_DOSStub_fc94 {
  strings:
    $key_fc94 = { a8 fc [2] dc e4 [2] 9b e6 [2] dc f7 [2] 92 fb [2] 9e f1 [2] 89 fa [2] 92 b4 [2] af }

  condition:
    any of them
}