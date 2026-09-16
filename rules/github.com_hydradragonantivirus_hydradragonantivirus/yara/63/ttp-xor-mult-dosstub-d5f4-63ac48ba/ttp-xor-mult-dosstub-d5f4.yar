rule TTP_XOR_MULT_DOSStub_d5f4 {
  strings:
    $key_d5f4 = { 81 9c [2] f5 84 [2] b2 86 [2] f5 97 [2] bb 9b [2] b7 91 [2] a0 9a [2] bb d4 [2] 86 }

  condition:
    any of them
}