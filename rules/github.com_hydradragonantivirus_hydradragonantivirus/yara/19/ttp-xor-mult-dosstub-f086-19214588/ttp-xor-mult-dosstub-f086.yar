rule TTP_XOR_MULT_DOSStub_f086 {
  strings:
    $key_f086 = { a4 ee [2] d0 f6 [2] 97 f4 [2] d0 e5 [2] 9e e9 [2] 92 e3 [2] 85 e8 [2] 9e a6 [2] a3 }

  condition:
    any of them
}