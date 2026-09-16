rule TTP_XOR_MULT_DOSStub_c5d8 {
  strings:
    $key_c5d8 = { 91 b0 [2] e5 a8 [2] a2 aa [2] e5 bb [2] ab b7 [2] a7 bd [2] b0 b6 [2] ab f8 [2] 96 }

  condition:
    any of them
}