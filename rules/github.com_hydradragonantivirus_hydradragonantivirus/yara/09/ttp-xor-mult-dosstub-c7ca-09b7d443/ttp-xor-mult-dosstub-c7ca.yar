rule TTP_XOR_MULT_DOSStub_c7ca {
  strings:
    $key_c7ca = { 93 a2 [2] e7 ba [2] a0 b8 [2] e7 a9 [2] a9 a5 [2] a5 af [2] b2 a4 [2] a9 ea [2] 94 }

  condition:
    any of them
}