rule TTP_XOR_MULT_DOSStub_64d9 {
  strings:
    $key_64d9 = { 30 b1 [2] 44 a9 [2] 03 ab [2] 44 ba [2] 0a b6 [2] 06 bc [2] 11 b7 [2] 0a f9 [2] 37 }

  condition:
    any of them
}