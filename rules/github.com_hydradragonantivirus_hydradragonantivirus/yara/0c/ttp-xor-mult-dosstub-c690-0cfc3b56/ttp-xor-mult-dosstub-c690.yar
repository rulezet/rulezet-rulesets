rule TTP_XOR_MULT_DOSStub_c690 {
  strings:
    $key_c690 = { 92 f8 [2] e6 e0 [2] a1 e2 [2] e6 f3 [2] a8 ff [2] a4 f5 [2] b3 fe [2] a8 b0 [2] 95 }

  condition:
    any of them
}