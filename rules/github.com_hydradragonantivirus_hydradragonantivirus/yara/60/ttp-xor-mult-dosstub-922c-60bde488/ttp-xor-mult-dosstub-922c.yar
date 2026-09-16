rule TTP_XOR_MULT_DOSStub_922c {
  strings:
    $key_922c = { c6 44 [2] b2 5c [2] f5 5e [2] b2 4f [2] fc 43 [2] f0 49 [2] e7 42 [2] fc 0c [2] c1 }

  condition:
    any of them
}