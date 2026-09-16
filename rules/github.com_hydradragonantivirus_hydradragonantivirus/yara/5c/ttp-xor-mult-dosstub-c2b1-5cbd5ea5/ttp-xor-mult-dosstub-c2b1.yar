rule TTP_XOR_MULT_DOSStub_c2b1 {
  strings:
    $key_c2b1 = { 96 d9 [2] e2 c1 [2] a5 c3 [2] e2 d2 [2] ac de [2] a0 d4 [2] b7 df [2] ac 91 [2] 91 }

  condition:
    any of them
}