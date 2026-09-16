rule TTP_XOR_MULT_DOSStub_d510 {
  strings:
    $key_d510 = { 81 78 [2] f5 60 [2] b2 62 [2] f5 73 [2] bb 7f [2] b7 75 [2] a0 7e [2] bb 30 [2] 86 }

  condition:
    any of them
}