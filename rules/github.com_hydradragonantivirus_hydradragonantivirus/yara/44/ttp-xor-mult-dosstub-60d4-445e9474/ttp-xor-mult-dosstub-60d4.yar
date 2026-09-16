rule TTP_XOR_MULT_DOSStub_60d4 {
  strings:
    $key_60d4 = { 34 bc [2] 40 a4 [2] 07 a6 [2] 40 b7 [2] 0e bb [2] 02 b1 [2] 15 ba [2] 0e f4 [2] 33 }

  condition:
    any of them
}