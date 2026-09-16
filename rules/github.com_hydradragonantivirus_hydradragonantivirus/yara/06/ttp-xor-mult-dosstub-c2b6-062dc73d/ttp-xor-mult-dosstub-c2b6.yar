rule TTP_XOR_MULT_DOSStub_c2b6 {
  strings:
    $key_c2b6 = { 96 de [2] e2 c6 [2] a5 c4 [2] e2 d5 [2] ac d9 [2] a0 d3 [2] b7 d8 [2] ac 96 [2] 91 }

  condition:
    any of them
}