rule TTP_XOR_MULT_DOSStub_d54d {
  strings:
    $key_d54d = { 81 25 [2] f5 3d [2] b2 3f [2] f5 2e [2] bb 22 [2] b7 28 [2] a0 23 [2] bb 6d [2] 86 }

  condition:
    any of them
}