rule TTP_XOR_MULT_DOSStub_c698 {
  strings:
    $key_c698 = { 92 f0 [2] e6 e8 [2] a1 ea [2] e6 fb [2] a8 f7 [2] a4 fd [2] b3 f6 [2] a8 b8 [2] 95 }

  condition:
    any of them
}