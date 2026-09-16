rule TTP_XOR_MULT_DOSStub_d395 {
  strings:
    $key_d395 = { 87 fd [2] f3 e5 [2] b4 e7 [2] f3 f6 [2] bd fa [2] b1 f0 [2] a6 fb [2] bd b5 [2] 80 }

  condition:
    any of them
}