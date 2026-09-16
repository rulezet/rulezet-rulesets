rule TTP_XOR_MULT_DOSStub_f0d6 {
  strings:
    $key_f0d6 = { a4 be [2] d0 a6 [2] 97 a4 [2] d0 b5 [2] 9e b9 [2] 92 b3 [2] 85 b8 [2] 9e f6 [2] a3 }

  condition:
    any of them
}