rule TTP_XOR_MULT_DOSStub_d4c5 {
  strings:
    $key_d4c5 = { 80 ad [2] f4 b5 [2] b3 b7 [2] f4 a6 [2] ba aa [2] b6 a0 [2] a1 ab [2] ba e5 [2] 87 }

  condition:
    any of them
}