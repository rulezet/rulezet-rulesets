rule TTP_XOR_MULT_DOSStub_d50d {
  strings:
    $key_d50d = { 81 65 [2] f5 7d [2] b2 7f [2] f5 6e [2] bb 62 [2] b7 68 [2] a0 63 [2] bb 2d [2] 86 }

  condition:
    any of them
}