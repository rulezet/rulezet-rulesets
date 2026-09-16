rule TTP_XOR_MULT_DOSStub_d57a {
  strings:
    $key_d57a = { 81 12 [2] f5 0a [2] b2 08 [2] f5 19 [2] bb 15 [2] b7 1f [2] a0 14 [2] bb 5a [2] 86 }

  condition:
    any of them
}