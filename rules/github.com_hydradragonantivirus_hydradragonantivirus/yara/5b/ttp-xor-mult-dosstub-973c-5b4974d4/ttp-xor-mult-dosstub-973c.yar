rule TTP_XOR_MULT_DOSStub_973c {
  strings:
    $key_973c = { c3 54 [2] b7 4c [2] f0 4e [2] b7 5f [2] f9 53 [2] f5 59 [2] e2 52 [2] f9 1c [2] c4 }

  condition:
    any of them
}