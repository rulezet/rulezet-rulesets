rule TTP_XOR_MULT_DOSStub_d55e {
  strings:
    $key_d55e = { 81 36 [2] f5 2e [2] b2 2c [2] f5 3d [2] bb 31 [2] b7 3b [2] a0 30 [2] bb 7e [2] 86 }

  condition:
    any of them
}