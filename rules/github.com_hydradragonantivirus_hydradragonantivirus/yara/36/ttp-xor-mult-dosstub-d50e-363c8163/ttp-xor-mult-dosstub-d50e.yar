rule TTP_XOR_MULT_DOSStub_d50e {
  strings:
    $key_d50e = { 81 66 [2] f5 7e [2] b2 7c [2] f5 6d [2] bb 61 [2] b7 6b [2] a0 60 [2] bb 2e [2] 86 }

  condition:
    any of them
}