rule TTP_XOR_MULT_DOSStub_f081 {
  strings:
    $key_f081 = { a4 e9 [2] d0 f1 [2] 97 f3 [2] d0 e2 [2] 9e ee [2] 92 e4 [2] 85 ef [2] 9e a1 [2] a3 }

  condition:
    any of them
}