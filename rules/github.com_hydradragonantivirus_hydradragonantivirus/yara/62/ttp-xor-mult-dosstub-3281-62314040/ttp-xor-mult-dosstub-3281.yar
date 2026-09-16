rule TTP_XOR_MULT_DOSStub_3281 {
  strings:
    $key_3281 = { 66 e9 [2] 12 f1 [2] 55 f3 [2] 12 e2 [2] 5c ee [2] 50 e4 [2] 47 ef [2] 5c a1 [2] 61 }

  condition:
    any of them
}