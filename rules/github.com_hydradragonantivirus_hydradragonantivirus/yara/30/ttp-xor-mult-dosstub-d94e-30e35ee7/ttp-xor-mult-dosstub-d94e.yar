rule TTP_XOR_MULT_DOSStub_d94e {
  strings:
    $key_d94e = { 8d 26 [2] f9 3e [2] be 3c [2] f9 2d [2] b7 21 [2] bb 2b [2] ac 20 [2] b7 6e [2] 8a }

  condition:
    any of them
}