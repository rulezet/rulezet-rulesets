rule TTP_XOR_MULT_DOSStub_64d2 {
  strings:
    $key_64d2 = { 30 ba [2] 44 a2 [2] 03 a0 [2] 44 b1 [2] 0a bd [2] 06 b7 [2] 11 bc [2] 0a f2 [2] 37 }

  condition:
    any of them
}