rule TTP_XOR_MULT_DOSStub_37d2 {
  strings:
    $key_37d2 = { 63 ba [2] 17 a2 [2] 50 a0 [2] 17 b1 [2] 59 bd [2] 55 b7 [2] 42 bc [2] 59 f2 [2] 64 }

  condition:
    any of them
}