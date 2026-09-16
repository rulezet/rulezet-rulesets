rule TTP_XOR_MULT_DOSStub_f396 {
  strings:
    $key_f396 = { a7 fe [2] d3 e6 [2] 94 e4 [2] d3 f5 [2] 9d f9 [2] 91 f3 [2] 86 f8 [2] 9d b6 [2] a0 }

  condition:
    any of them
}