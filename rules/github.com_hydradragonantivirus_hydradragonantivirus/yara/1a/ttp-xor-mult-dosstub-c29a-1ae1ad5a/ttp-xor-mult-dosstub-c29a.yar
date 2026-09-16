rule TTP_XOR_MULT_DOSStub_c29a {
  strings:
    $key_c29a = { 96 f2 [2] e2 ea [2] a5 e8 [2] e2 f9 [2] ac f5 [2] a0 ff [2] b7 f4 [2] ac ba [2] 91 }

  condition:
    any of them
}