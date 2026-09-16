rule TTP_XOR_MULT_DOSStub_f390 {
  strings:
    $key_f390 = { a7 f8 [2] d3 e0 [2] 94 e2 [2] d3 f3 [2] 9d ff [2] 91 f5 [2] 86 fe [2] 9d b0 [2] a0 }

  condition:
    any of them
}