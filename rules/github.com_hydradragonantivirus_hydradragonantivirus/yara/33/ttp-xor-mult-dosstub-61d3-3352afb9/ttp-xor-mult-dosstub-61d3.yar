rule TTP_XOR_MULT_DOSStub_61d3 {
  strings:
    $key_61d3 = { 35 bb [2] 41 a3 [2] 06 a1 [2] 41 b0 [2] 0f bc [2] 03 b6 [2] 14 bd [2] 0f f3 [2] 32 }

  condition:
    any of them
}