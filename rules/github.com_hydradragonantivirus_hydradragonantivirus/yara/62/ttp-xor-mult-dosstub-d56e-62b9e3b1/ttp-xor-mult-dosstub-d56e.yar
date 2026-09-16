rule TTP_XOR_MULT_DOSStub_d56e {
  strings:
    $key_d56e = { 81 06 [2] f5 1e [2] b2 1c [2] f5 0d [2] bb 01 [2] b7 0b [2] a0 00 [2] bb 4e [2] 86 }

  condition:
    any of them
}