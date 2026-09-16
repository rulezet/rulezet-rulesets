rule TTP_XOR_MULT_DOSStub_d95b {
  strings:
    $key_d95b = { 8d 33 [2] f9 2b [2] be 29 [2] f9 38 [2] b7 34 [2] bb 3e [2] ac 35 [2] b7 7b [2] 8a }

  condition:
    any of them
}