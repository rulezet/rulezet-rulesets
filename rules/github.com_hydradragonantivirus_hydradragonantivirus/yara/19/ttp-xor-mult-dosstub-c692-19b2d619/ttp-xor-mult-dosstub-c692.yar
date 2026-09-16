rule TTP_XOR_MULT_DOSStub_c692 {
  strings:
    $key_c692 = { 92 fa [2] e6 e2 [2] a1 e0 [2] e6 f1 [2] a8 fd [2] a4 f7 [2] b3 fc [2] a8 b2 [2] 95 }

  condition:
    any of them
}