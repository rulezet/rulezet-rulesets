rule TTP_XOR_MULT_DOSStub_918b {
  strings:
    $key_918b = { c5 e3 [2] b1 fb [2] f6 f9 [2] b1 e8 [2] ff e4 [2] f3 ee [2] e4 e5 [2] ff ab [2] c2 }

  condition:
    any of them
}