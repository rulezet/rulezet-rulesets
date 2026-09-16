rule TTP_XOR_MULT_DOSStub_d07e {
  strings:
    $key_d07e = { 84 16 [2] f0 0e [2] b7 0c [2] f0 1d [2] be 11 [2] b2 1b [2] a5 10 [2] be 5e [2] 83 }

  condition:
    any of them
}