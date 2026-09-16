rule TTP_XOR_MULT_DOSStub_f3cb {
  strings:
    $key_f3cb = { a7 a3 [2] d3 bb [2] 94 b9 [2] d3 a8 [2] 9d a4 [2] 91 ae [2] 86 a5 [2] 9d eb [2] a0 }

  condition:
    any of them
}