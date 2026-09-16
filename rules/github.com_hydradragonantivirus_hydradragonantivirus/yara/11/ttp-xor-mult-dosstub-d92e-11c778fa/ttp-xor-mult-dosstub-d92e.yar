rule TTP_XOR_MULT_DOSStub_d92e {
  strings:
    $key_d92e = { 8d 46 [2] f9 5e [2] be 5c [2] f9 4d [2] b7 41 [2] bb 4b [2] ac 40 [2] b7 0e [2] 8a }

  condition:
    any of them
}