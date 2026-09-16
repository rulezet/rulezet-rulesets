rule TTP_XOR_MULT_DOSStub_d0e1 {
  strings:
    $key_d0e1 = { 84 89 [2] f0 91 [2] b7 93 [2] f0 82 [2] be 8e [2] b2 84 [2] a5 8f [2] be c1 [2] 83 }

  condition:
    any of them
}