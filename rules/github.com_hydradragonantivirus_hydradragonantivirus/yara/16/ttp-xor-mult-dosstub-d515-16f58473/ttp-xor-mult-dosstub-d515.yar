rule TTP_XOR_MULT_DOSStub_d515 {
  strings:
    $key_d515 = { 81 7d [2] f5 65 [2] b2 67 [2] f5 76 [2] bb 7a [2] b7 70 [2] a0 7b [2] bb 35 [2] 86 }

  condition:
    any of them
}