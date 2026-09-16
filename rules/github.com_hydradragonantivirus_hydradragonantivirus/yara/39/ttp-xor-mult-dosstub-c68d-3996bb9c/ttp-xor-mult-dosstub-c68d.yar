rule TTP_XOR_MULT_DOSStub_c68d {
  strings:
    $key_c68d = { 92 e5 [2] e6 fd [2] a1 ff [2] e6 ee [2] a8 e2 [2] a4 e8 [2] b3 e3 [2] a8 ad [2] 95 }

  condition:
    any of them
}