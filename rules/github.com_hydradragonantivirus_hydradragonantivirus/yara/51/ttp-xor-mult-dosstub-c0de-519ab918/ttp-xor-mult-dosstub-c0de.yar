rule TTP_XOR_MULT_DOSStub_c0de {
  strings:
    $key_c0de = { 94 b6 [2] e0 ae [2] a7 ac [2] e0 bd [2] ae b1 [2] a2 bb [2] b5 b0 [2] ae fe [2] 93 }

  condition:
    any of them
}