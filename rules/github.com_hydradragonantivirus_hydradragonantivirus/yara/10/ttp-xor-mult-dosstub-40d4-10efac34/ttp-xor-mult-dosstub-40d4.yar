rule TTP_XOR_MULT_DOSStub_40d4 {
  strings:
    $key_40d4 = { 14 bc [2] 60 a4 [2] 27 a6 [2] 60 b7 [2] 2e bb [2] 22 b1 [2] 35 ba [2] 2e f4 [2] 13 }

  condition:
    any of them
}