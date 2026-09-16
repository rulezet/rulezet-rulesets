rule TTP_XOR_MULT_DOSStub_f5b4 {
  strings:
    $key_f5b4 = { a1 dc [2] d5 c4 [2] 92 c6 [2] d5 d7 [2] 9b db [2] 97 d1 [2] 80 da [2] 9b 94 [2] a6 }

  condition:
    any of them
}