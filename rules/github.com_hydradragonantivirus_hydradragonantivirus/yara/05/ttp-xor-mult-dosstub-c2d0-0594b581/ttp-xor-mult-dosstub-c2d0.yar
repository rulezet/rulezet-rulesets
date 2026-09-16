rule TTP_XOR_MULT_DOSStub_c2d0 {
  strings:
    $key_c2d0 = { 96 b8 [2] e2 a0 [2] a5 a2 [2] e2 b3 [2] ac bf [2] a0 b5 [2] b7 be [2] ac f0 [2] 91 }

  condition:
    any of them
}