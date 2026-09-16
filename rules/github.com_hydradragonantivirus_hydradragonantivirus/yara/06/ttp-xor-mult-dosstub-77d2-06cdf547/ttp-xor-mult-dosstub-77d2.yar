rule TTP_XOR_MULT_DOSStub_77d2 {
  strings:
    $key_77d2 = { 23 ba [2] 57 a2 [2] 10 a0 [2] 57 b1 [2] 19 bd [2] 15 b7 [2] 02 bc [2] 19 f2 [2] 24 }

  condition:
    any of them
}