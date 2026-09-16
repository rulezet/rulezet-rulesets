rule TTP_XOR_MULT_DOSStub_d695 {
  strings:
    $key_d695 = { 82 fd [2] f6 e5 [2] b1 e7 [2] f6 f6 [2] b8 fa [2] b4 f0 [2] a3 fb [2] b8 b5 [2] 85 }

  condition:
    any of them
}