rule TTP_XOR_MULT_DOSStub_f781 {
  strings:
    $key_f781 = { a3 e9 [2] d7 f1 [2] 90 f3 [2] d7 e2 [2] 99 ee [2] 95 e4 [2] 82 ef [2] 99 a1 [2] a4 }

  condition:
    any of them
}