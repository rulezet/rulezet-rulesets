rule TTP_XOR_MULT_DOSStub_d04c {
  strings:
    $key_d04c = { 84 24 [2] f0 3c [2] b7 3e [2] f0 2f [2] be 23 [2] b2 29 [2] a5 22 [2] be 6c [2] 83 }

  condition:
    any of them
}