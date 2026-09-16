rule TTP_XOR_MULT_DOSStub_f59a {
  strings:
    $key_f59a = { a1 f2 [2] d5 ea [2] 92 e8 [2] d5 f9 [2] 9b f5 [2] 97 ff [2] 80 f4 [2] 9b ba [2] a6 }

  condition:
    any of them
}