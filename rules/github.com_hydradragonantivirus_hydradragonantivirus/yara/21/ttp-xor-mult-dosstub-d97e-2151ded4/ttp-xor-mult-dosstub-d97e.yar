rule TTP_XOR_MULT_DOSStub_d97e {
  strings:
    $key_d97e = { 8d 16 [2] f9 0e [2] be 0c [2] f9 1d [2] b7 11 [2] bb 1b [2] ac 10 [2] b7 5e [2] 8a }

  condition:
    any of them
}