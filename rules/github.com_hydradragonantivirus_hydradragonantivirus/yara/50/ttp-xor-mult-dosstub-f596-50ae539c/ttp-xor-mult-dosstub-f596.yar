rule TTP_XOR_MULT_DOSStub_f596 {
  strings:
    $key_f596 = { a1 fe [2] d5 e6 [2] 92 e4 [2] d5 f5 [2] 9b f9 [2] 97 f3 [2] 80 f8 [2] 9b b6 [2] a6 }

  condition:
    any of them
}