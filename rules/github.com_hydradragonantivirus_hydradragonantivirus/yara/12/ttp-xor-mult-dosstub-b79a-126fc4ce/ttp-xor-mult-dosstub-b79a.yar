rule TTP_XOR_MULT_DOSStub_b79a {
  strings:
    $key_b79a = { e3 f2 [2] 97 ea [2] d0 e8 [2] 97 f9 [2] d9 f5 [2] d5 ff [2] c2 f4 [2] d9 ba [2] e4 }

  condition:
    any of them
}