rule TTP_XOR_MULT_DOSStub_50d4 {
  strings:
    $key_50d4 = { 04 bc [2] 70 a4 [2] 37 a6 [2] 70 b7 [2] 3e bb [2] 32 b1 [2] 25 ba [2] 3e f4 [2] 03 }

  condition:
    any of them
}