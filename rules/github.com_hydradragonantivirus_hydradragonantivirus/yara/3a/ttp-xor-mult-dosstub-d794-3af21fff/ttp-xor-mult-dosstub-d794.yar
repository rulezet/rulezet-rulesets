rule TTP_XOR_MULT_DOSStub_d794 {
  strings:
    $key_d794 = { 83 fc [2] f7 e4 [2] b0 e6 [2] f7 f7 [2] b9 fb [2] b5 f1 [2] a2 fa [2] b9 b4 [2] 84 }

  condition:
    any of them
}