rule TTP_XOR_MULT_DOSStub_d933 {
  strings:
    $key_d933 = { 8d 5b [2] f9 43 [2] be 41 [2] f9 50 [2] b7 5c [2] bb 56 [2] ac 5d [2] b7 13 [2] 8a }

  condition:
    any of them
}