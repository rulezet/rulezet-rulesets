rule TTP_XOR_MULT_DOSStub_64d4 {
  strings:
    $key_64d4 = { 30 bc [2] 44 a4 [2] 03 a6 [2] 44 b7 [2] 0a bb [2] 06 b1 [2] 11 ba [2] 0a f4 [2] 37 }

  condition:
    any of them
}