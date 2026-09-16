rule TTP_XOR_MULT_DOSStub_cc94 {
  strings:
    $key_cc94 = { 98 fc [2] ec e4 [2] ab e6 [2] ec f7 [2] a2 fb [2] ae f1 [2] b9 fa [2] a2 b4 [2] 9f }

  condition:
    any of them
}