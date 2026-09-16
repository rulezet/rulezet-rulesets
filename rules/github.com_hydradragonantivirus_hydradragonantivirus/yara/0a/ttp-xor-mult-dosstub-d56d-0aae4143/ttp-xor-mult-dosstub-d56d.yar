rule TTP_XOR_MULT_DOSStub_d56d {
  strings:
    $key_d56d = { 81 05 [2] f5 1d [2] b2 1f [2] f5 0e [2] bb 02 [2] b7 08 [2] a0 03 [2] bb 4d [2] 86 }

  condition:
    any of them
}