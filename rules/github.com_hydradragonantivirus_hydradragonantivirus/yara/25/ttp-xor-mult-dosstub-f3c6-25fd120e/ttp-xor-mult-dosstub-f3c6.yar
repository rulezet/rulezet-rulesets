rule TTP_XOR_MULT_DOSStub_f3c6 {
  strings:
    $key_f3c6 = { a7 ae [2] d3 b6 [2] 94 b4 [2] d3 a5 [2] 9d a9 [2] 91 a3 [2] 86 a8 [2] 9d e6 [2] a0 }

  condition:
    any of them
}