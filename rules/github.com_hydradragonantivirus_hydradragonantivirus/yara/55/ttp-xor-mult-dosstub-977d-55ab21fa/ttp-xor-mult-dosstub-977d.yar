rule TTP_XOR_MULT_DOSStub_977d {
  strings:
    $key_977d = { c3 15 [2] b7 0d [2] f0 0f [2] b7 1e [2] f9 12 [2] f5 18 [2] e2 13 [2] f9 5d [2] c4 }

  condition:
    any of them
}