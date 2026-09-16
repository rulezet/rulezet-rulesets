rule TTP_XOR_MULT_DOSStub_923c {
  strings:
    $key_923c = { c6 54 [2] b2 4c [2] f5 4e [2] b2 5f [2] fc 53 [2] f0 59 [2] e7 52 [2] fc 1c [2] c1 }

  condition:
    any of them
}