rule TTP_XOR_MULT_DOSStub_d526 {
  strings:
    $key_d526 = { 81 4e [2] f5 56 [2] b2 54 [2] f5 45 [2] bb 49 [2] b7 43 [2] a0 48 [2] bb 06 [2] 86 }

  condition:
    any of them
}