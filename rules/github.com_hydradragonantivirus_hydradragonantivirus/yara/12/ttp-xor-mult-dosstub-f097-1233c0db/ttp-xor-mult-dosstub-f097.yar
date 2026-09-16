rule TTP_XOR_MULT_DOSStub_f097 {
  strings:
    $key_f097 = { a4 ff [2] d0 e7 [2] 97 e5 [2] d0 f4 [2] 9e f8 [2] 92 f2 [2] 85 f9 [2] 9e b7 [2] a3 }

  condition:
    any of them
}