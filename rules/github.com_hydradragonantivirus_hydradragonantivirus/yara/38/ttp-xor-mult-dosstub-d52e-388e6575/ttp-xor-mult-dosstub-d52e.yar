rule TTP_XOR_MULT_DOSStub_d52e {
  strings:
    $key_d52e = { 81 46 [2] f5 5e [2] b2 5c [2] f5 4d [2] bb 41 [2] b7 4b [2] a0 40 [2] bb 0e [2] 86 }

  condition:
    any of them
}