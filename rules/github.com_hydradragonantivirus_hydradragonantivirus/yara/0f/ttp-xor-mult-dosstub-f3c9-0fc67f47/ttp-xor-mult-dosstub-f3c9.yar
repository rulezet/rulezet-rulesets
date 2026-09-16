rule TTP_XOR_MULT_DOSStub_f3c9 {
  strings:
    $key_f3c9 = { a7 a1 [2] d3 b9 [2] 94 bb [2] d3 aa [2] 9d a6 [2] 91 ac [2] 86 a7 [2] 9d e9 [2] a0 }

  condition:
    any of them
}