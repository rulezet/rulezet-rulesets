rule TTP_XOR_MULT_DOSStub_a79a {
  strings:
    $key_a79a = { f3 f2 [2] 87 ea [2] c0 e8 [2] 87 f9 [2] c9 f5 [2] c5 ff [2] d2 f4 [2] c9 ba [2] f4 }

  condition:
    any of them
}