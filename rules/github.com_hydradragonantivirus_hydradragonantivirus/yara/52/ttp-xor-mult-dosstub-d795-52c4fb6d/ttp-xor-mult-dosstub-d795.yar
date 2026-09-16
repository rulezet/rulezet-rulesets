rule TTP_XOR_MULT_DOSStub_d795 {
  strings:
    $key_d795 = { 83 fd [2] f7 e5 [2] b0 e7 [2] f7 f6 [2] b9 fa [2] b5 f0 [2] a2 fb [2] b9 b5 [2] 84 }

  condition:
    any of them
}