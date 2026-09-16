rule TTP_XOR_MULT_DOSStub_d55f {
  strings:
    $key_d55f = { 81 37 [2] f5 2f [2] b2 2d [2] f5 3c [2] bb 30 [2] b7 3a [2] a0 31 [2] bb 7f [2] 86 }

  condition:
    any of them
}