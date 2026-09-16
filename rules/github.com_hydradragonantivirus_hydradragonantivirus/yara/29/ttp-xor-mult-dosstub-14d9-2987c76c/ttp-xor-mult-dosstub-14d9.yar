rule TTP_XOR_MULT_DOSStub_14d9 {
  strings:
    $key_14d9 = { 40 b1 [2] 34 a9 [2] 73 ab [2] 34 ba [2] 7a b6 [2] 76 bc [2] 61 b7 [2] 7a f9 [2] 47 }

  condition:
    any of them
}