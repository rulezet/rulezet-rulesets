rule TTP_XOR_MULT_DOSStub_d513 {
  strings:
    $key_d513 = { 81 7b [2] f5 63 [2] b2 61 [2] f5 70 [2] bb 7c [2] b7 76 [2] a0 7d [2] bb 33 [2] 86 }

  condition:
    any of them
}