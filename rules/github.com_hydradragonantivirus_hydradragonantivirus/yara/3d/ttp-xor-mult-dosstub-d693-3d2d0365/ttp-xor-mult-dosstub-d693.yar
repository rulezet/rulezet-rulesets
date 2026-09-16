rule TTP_XOR_MULT_DOSStub_d693 {
  strings:
    $key_d693 = { 82 fb [2] f6 e3 [2] b1 e1 [2] f6 f0 [2] b8 fc [2] b4 f6 [2] a3 fd [2] b8 b3 [2] 85 }

  condition:
    any of them
}