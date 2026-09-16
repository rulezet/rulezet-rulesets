rule TTP_XOR_MULT_DOSStub_f386 {
  strings:
    $key_f386 = { a7 ee [2] d3 f6 [2] 94 f4 [2] d3 e5 [2] 9d e9 [2] 91 e3 [2] 86 e8 [2] 9d a6 [2] a0 }

  condition:
    any of them
}