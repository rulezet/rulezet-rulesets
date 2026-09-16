rule TTP_XOR_MULT_DOSStub_f29a {
  strings:
    $key_f29a = { a6 f2 [2] d2 ea [2] 95 e8 [2] d2 f9 [2] 9c f5 [2] 90 ff [2] 87 f4 [2] 9c ba [2] a1 }

  condition:
    any of them
}