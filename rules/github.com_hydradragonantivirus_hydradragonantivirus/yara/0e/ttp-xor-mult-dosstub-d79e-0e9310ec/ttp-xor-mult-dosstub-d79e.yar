rule TTP_XOR_MULT_DOSStub_d79e {
  strings:
    $key_d79e = { 83 f6 [2] f7 ee [2] b0 ec [2] f7 fd [2] b9 f1 [2] b5 fb [2] a2 f0 [2] b9 be [2] 84 }

  condition:
    any of them
}