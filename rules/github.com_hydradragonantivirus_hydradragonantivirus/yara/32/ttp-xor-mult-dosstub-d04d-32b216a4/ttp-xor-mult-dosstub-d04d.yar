rule TTP_XOR_MULT_DOSStub_d04d {
  strings:
    $key_d04d = { 84 25 [2] f0 3d [2] b7 3f [2] f0 2e [2] be 22 [2] b2 28 [2] a5 23 [2] be 6d [2] 83 }

  condition:
    any of them
}