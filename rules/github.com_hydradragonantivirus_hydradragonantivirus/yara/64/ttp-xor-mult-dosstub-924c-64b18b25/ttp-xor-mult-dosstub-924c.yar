rule TTP_XOR_MULT_DOSStub_924c {
  strings:
    $key_924c = { c6 24 [2] b2 3c [2] f5 3e [2] b2 2f [2] fc 23 [2] f0 29 [2] e7 22 [2] fc 6c [2] c1 }

  condition:
    any of them
}