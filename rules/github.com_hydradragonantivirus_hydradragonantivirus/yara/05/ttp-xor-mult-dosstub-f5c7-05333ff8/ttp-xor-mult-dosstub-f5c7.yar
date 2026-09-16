rule TTP_XOR_MULT_DOSStub_f5c7 {
  strings:
    $key_f5c7 = { a1 af [2] d5 b7 [2] 92 b5 [2] d5 a4 [2] 9b a8 [2] 97 a2 [2] 80 a9 [2] 9b e7 [2] a6 }

  condition:
    any of them
}