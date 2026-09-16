rule TTP_XOR_MULT_DOSStub_f09a {
  strings:
    $key_f09a = { a4 f2 [2] d0 ea [2] 97 e8 [2] d0 f9 [2] 9e f5 [2] 92 ff [2] 85 f4 [2] 9e ba [2] a3 }

  condition:
    any of them
}