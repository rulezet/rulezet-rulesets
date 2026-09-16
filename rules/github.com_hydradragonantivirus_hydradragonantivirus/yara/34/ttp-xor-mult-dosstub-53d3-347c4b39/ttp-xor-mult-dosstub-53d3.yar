rule TTP_XOR_MULT_DOSStub_53d3 {
  strings:
    $key_53d3 = { 07 bb [2] 73 a3 [2] 34 a1 [2] 73 b0 [2] 3d bc [2] 31 b6 [2] 26 bd [2] 3d f3 [2] 00 }

  condition:
    any of them
}