rule TTP_XOR_MULT_DOSStub_c69a {
  strings:
    $key_c69a = { 92 f2 [2] e6 ea [2] a1 e8 [2] e6 f9 [2] a8 f5 [2] a4 ff [2] b3 f4 [2] a8 ba [2] 95 }

  condition:
    any of them
}