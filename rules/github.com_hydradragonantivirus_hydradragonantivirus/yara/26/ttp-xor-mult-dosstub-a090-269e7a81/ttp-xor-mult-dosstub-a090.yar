rule TTP_XOR_MULT_DOSStub_a090 {
  strings:
    $key_a090 = { f4 f8 [2] 80 e0 [2] c7 e2 [2] 80 f3 [2] ce ff [2] c2 f5 [2] d5 fe [2] ce b0 [2] f3 }

  condition:
    any of them
}