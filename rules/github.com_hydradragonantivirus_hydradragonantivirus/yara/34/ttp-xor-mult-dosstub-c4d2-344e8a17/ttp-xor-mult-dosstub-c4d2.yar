rule TTP_XOR_MULT_DOSStub_c4d2 {
  strings:
    $key_c4d2 = { 90 ba [2] e4 a2 [2] a3 a0 [2] e4 b1 [2] aa bd [2] a6 b7 [2] b1 bc [2] aa f2 [2] 97 }

  condition:
    any of them
}