rule TTP_XOR_MULT_DOSStub_13d4 {
  strings:
    $key_13d4 = { 47 bc [2] 33 a4 [2] 74 a6 [2] 33 b7 [2] 7d bb [2] 71 b1 [2] 66 ba [2] 7d f4 [2] 40 }

  condition:
    any of them
}