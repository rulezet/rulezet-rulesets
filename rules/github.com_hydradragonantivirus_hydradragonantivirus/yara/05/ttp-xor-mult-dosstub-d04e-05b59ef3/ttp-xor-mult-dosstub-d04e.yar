rule TTP_XOR_MULT_DOSStub_d04e {
  strings:
    $key_d04e = { 84 26 [2] f0 3e [2] b7 3c [2] f0 2d [2] be 21 [2] b2 2b [2] a5 20 [2] be 6e [2] 83 }

  condition:
    any of them
}