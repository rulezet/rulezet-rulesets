rule TTP_XOR_MULT_DOSStub_f281 {
  strings:
    $key_f281 = { a6 e9 [2] d2 f1 [2] 95 f3 [2] d2 e2 [2] 9c ee [2] 90 e4 [2] 87 ef [2] 9c a1 [2] a1 }

  condition:
    any of them
}