rule TTP_XOR_MULT_DOSStub_f4cb {
  strings:
    $key_f4cb = { a0 a3 [2] d4 bb [2] 93 b9 [2] d4 a8 [2] 9a a4 [2] 96 ae [2] 81 a5 [2] 9a eb [2] a7 }

  condition:
    any of them
}