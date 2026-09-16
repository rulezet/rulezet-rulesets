rule TTP_XOR_MULT_DOSStub_f1cb {
  strings:
    $key_f1cb = { a5 a3 [2] d1 bb [2] 96 b9 [2] d1 a8 [2] 9f a4 [2] 93 ae [2] 84 a5 [2] 9f eb [2] a2 }

  condition:
    any of them
}