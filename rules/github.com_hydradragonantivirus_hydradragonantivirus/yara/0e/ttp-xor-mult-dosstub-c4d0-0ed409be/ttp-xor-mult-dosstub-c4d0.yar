rule TTP_XOR_MULT_DOSStub_c4d0 {
  strings:
    $key_c4d0 = { 90 b8 [2] e4 a0 [2] a3 a2 [2] e4 b3 [2] aa bf [2] a6 b5 [2] b1 be [2] aa f0 [2] 97 }

  condition:
    any of them
}