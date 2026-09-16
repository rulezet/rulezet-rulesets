rule TTP_XOR_MULT_DOSStub_f6d3 {
  strings:
    $key_f6d3 = { a2 bb [2] d6 a3 [2] 91 a1 [2] d6 b0 [2] 98 bc [2] 94 b6 [2] 83 bd [2] 98 f3 [2] a5 }

  condition:
    any of them
}