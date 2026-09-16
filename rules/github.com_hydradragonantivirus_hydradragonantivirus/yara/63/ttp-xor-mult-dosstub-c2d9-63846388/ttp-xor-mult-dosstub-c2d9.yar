rule TTP_XOR_MULT_DOSStub_c2d9 {
  strings:
    $key_c2d9 = { 96 b1 [2] e2 a9 [2] a5 ab [2] e2 ba [2] ac b6 [2] a0 bc [2] b7 b7 [2] ac f9 [2] 91 }

  condition:
    any of them
}