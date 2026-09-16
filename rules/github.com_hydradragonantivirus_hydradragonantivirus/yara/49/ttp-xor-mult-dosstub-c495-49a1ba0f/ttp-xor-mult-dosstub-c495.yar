rule TTP_XOR_MULT_DOSStub_c495 {
  strings:
    $key_c495 = { 90 fd [2] e4 e5 [2] a3 e7 [2] e4 f6 [2] aa fa [2] a6 f0 [2] b1 fb [2] aa b5 [2] 97 }

  condition:
    any of them
}