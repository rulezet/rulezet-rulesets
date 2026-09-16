rule TTP_XOR_MULT_DOSStub_11d3 {
  strings:
    $key_11d3 = { 45 bb [2] 31 a3 [2] 76 a1 [2] 31 b0 [2] 7f bc [2] 73 b6 [2] 64 bd [2] 7f f3 [2] 42 }

  condition:
    any of them
}