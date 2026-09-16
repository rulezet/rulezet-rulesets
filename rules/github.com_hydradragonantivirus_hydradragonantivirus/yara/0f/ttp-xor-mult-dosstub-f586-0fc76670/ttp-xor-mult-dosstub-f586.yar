rule TTP_XOR_MULT_DOSStub_f586 {
  strings:
    $key_f586 = { a1 ee [2] d5 f6 [2] 92 f4 [2] d5 e5 [2] 9b e9 [2] 97 e3 [2] 80 e8 [2] 9b a6 [2] a6 }

  condition:
    any of them
}