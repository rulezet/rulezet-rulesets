rule TTP_XOR_MULT_DOSStub_c4a6 {
  strings:
    $key_c4a6 = { 90 ce [2] e4 d6 [2] a3 d4 [2] e4 c5 [2] aa c9 [2] a6 c3 [2] b1 c8 [2] aa 86 [2] 97 }

  condition:
    any of them
}