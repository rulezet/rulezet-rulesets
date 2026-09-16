rule TTP_XOR_MULT_DOSStub_c2b0 {
  strings:
    $key_c2b0 = { 96 d8 [2] e2 c0 [2] a5 c2 [2] e2 d3 [2] ac df [2] a0 d5 [2] b7 de [2] ac 90 [2] 91 }

  condition:
    any of them
}