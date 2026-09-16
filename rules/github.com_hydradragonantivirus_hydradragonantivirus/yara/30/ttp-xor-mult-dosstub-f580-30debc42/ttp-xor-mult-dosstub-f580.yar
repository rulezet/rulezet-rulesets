rule TTP_XOR_MULT_DOSStub_f580 {
  strings:
    $key_f580 = { a1 e8 [2] d5 f0 [2] 92 f2 [2] d5 e3 [2] 9b ef [2] 97 e5 [2] 80 ee [2] 9b a0 [2] a6 }

  condition:
    any of them
}