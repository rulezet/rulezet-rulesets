rule TTP_XOR_MULT_DOSStub_14d2 {
  strings:
    $key_14d2 = { 40 ba [2] 34 a2 [2] 73 a0 [2] 34 b1 [2] 7a bd [2] 76 b7 [2] 61 bc [2] 7a f2 [2] 47 }

  condition:
    any of them
}