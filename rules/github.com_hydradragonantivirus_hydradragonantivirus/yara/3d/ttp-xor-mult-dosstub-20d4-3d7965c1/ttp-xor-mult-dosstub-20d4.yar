rule TTP_XOR_MULT_DOSStub_20d4 {
  strings:
    $key_20d4 = { 74 bc [2] 00 a4 [2] 47 a6 [2] 00 b7 [2] 4e bb [2] 42 b1 [2] 55 ba [2] 4e f4 [2] 73 }

  condition:
    any of them
}