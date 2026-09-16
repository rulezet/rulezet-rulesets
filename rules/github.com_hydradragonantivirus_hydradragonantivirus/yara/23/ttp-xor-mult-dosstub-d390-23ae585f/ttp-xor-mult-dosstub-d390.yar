rule TTP_XOR_MULT_DOSStub_d390 {
  strings:
    $key_d390 = { 87 f8 [2] f3 e0 [2] b4 e2 [2] f3 f3 [2] bd ff [2] b1 f5 [2] a6 fe [2] bd b0 [2] 80 }

  condition:
    any of them
}