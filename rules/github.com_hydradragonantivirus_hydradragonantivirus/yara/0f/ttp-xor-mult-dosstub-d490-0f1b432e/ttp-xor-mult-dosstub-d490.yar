rule TTP_XOR_MULT_DOSStub_d490 {
  strings:
    $key_d490 = { 80 f8 [2] f4 e0 [2] b3 e2 [2] f4 f3 [2] ba ff [2] b6 f5 [2] a1 fe [2] ba b0 [2] 87 }

  condition:
    any of them
}