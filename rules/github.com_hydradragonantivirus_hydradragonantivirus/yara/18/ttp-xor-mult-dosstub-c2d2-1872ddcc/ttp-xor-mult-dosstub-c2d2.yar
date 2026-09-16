rule TTP_XOR_MULT_DOSStub_c2d2 {
  strings:
    $key_c2d2 = { 96 ba [2] e2 a2 [2] a5 a0 [2] e2 b1 [2] ac bd [2] a0 b7 [2] b7 bc [2] ac f2 [2] 91 }

  condition:
    any of them
}