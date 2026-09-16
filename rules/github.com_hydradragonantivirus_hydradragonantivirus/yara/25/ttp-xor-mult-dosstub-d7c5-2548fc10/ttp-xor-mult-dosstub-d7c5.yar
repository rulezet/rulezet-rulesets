rule TTP_XOR_MULT_DOSStub_d7c5 {
  strings:
    $key_d7c5 = { 83 ad [2] f7 b5 [2] b0 b7 [2] f7 a6 [2] b9 aa [2] b5 a0 [2] a2 ab [2] b9 e5 [2] 84 }

  condition:
    any of them
}