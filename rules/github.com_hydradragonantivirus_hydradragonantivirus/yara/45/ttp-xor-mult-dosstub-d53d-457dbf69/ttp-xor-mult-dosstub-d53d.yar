rule TTP_XOR_MULT_DOSStub_d53d {
  strings:
    $key_d53d = { 81 55 [2] f5 4d [2] b2 4f [2] f5 5e [2] bb 52 [2] b7 58 [2] a0 53 [2] bb 1d [2] 86 }

  condition:
    any of them
}