rule TTP_XOR_MULT_DOSStub_f5c6 {
  strings:
    $key_f5c6 = { a1 ae [2] d5 b6 [2] 92 b4 [2] d5 a5 [2] 9b a9 [2] 97 a3 [2] 80 a8 [2] 9b e6 [2] a6 }

  condition:
    any of them
}