rule TTP_XOR_MULT_DOSStub_d93e {
  strings:
    $key_d93e = { 8d 56 [2] f9 4e [2] be 4c [2] f9 5d [2] b7 51 [2] bb 5b [2] ac 50 [2] b7 1e [2] 8a }

  condition:
    any of them
}