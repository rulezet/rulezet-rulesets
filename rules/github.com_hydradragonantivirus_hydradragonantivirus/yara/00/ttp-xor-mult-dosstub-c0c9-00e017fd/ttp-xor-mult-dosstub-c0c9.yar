rule TTP_XOR_MULT_DOSStub_c0c9 {
  strings:
    $key_c0c9 = { 94 a1 [2] e0 b9 [2] a7 bb [2] e0 aa [2] ae a6 [2] a2 ac [2] b5 a7 [2] ae e9 [2] 93 }

  condition:
    any of them
}