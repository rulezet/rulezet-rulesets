rule TTP_XOR_MULT_DOSStub_70d4 {
  strings:
    $key_70d4 = { 24 bc [2] 50 a4 [2] 17 a6 [2] 50 b7 [2] 1e bb [2] 12 b1 [2] 05 ba [2] 1e f4 [2] 23 }

  condition:
    any of them
}