rule TTP_XOR_MULT_DOSStub_c4c8 {
  strings:
    $key_c4c8 = { 90 a0 [2] e4 b8 [2] a3 ba [2] e4 ab [2] aa a7 [2] a6 ad [2] b1 a6 [2] aa e8 [2] 97 }

  condition:
    any of them
}