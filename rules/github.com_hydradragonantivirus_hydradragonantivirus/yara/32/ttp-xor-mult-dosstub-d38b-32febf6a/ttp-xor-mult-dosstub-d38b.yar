rule TTP_XOR_MULT_DOSStub_d38b {
  strings:
    $key_d38b = { 87 e3 [2] f3 fb [2] b4 f9 [2] f3 e8 [2] bd e4 [2] b1 ee [2] a6 e5 [2] bd ab [2] 80 }

  condition:
    any of them
}