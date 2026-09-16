rule TTP_XOR_MULT_DOSStub_a0d0 {
  strings:
    $key_a0d0 = { f4 b8 [2] 80 a0 [2] c7 a2 [2] 80 b3 [2] ce bf [2] c2 b5 [2] d5 be [2] ce f0 [2] f3 }

  condition:
    any of them
}