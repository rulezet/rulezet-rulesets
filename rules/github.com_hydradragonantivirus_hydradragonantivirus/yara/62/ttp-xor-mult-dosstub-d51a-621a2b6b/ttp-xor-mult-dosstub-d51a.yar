rule TTP_XOR_MULT_DOSStub_d51a {
  strings:
    $key_d51a = { 81 72 [2] f5 6a [2] b2 68 [2] f5 79 [2] bb 75 [2] b7 7f [2] a0 74 [2] bb 3a [2] 86 }

  condition:
    any of them
}