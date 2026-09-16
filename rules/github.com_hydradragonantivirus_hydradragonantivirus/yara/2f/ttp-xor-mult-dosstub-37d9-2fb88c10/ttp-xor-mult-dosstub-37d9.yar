rule TTP_XOR_MULT_DOSStub_37d9 {
  strings:
    $key_37d9 = { 63 b1 [2] 17 a9 [2] 50 ab [2] 17 ba [2] 59 b6 [2] 55 bc [2] 42 b7 [2] 59 f9 [2] 64 }

  condition:
    any of them
}