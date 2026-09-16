rule TTP_XOR_MULT_DOSStub_d06e {
  strings:
    $key_d06e = { 84 06 [2] f0 1e [2] b7 1c [2] f0 0d [2] be 01 [2] b2 0b [2] a5 00 [2] be 4e [2] 83 }

  condition:
    any of them
}