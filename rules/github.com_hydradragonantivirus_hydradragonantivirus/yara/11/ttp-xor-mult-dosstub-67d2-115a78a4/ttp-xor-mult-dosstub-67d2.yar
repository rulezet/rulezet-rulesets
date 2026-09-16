rule TTP_XOR_MULT_DOSStub_67d2 {
  strings:
    $key_67d2 = { 33 ba [2] 47 a2 [2] 00 a0 [2] 47 b1 [2] 09 bd [2] 05 b7 [2] 12 bc [2] 09 f2 [2] 34 }

  condition:
    any of them
}