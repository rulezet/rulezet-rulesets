rule TTP_XOR_MULT_DOSStub_04d4 {
  strings:
    $key_04d4 = { 50 bc [2] 24 a4 [2] 63 a6 [2] 24 b7 [2] 6a bb [2] 66 b1 [2] 71 ba [2] 6a f4 [2] 57 }

  condition:
    any of them
}