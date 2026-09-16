rule TTP_XOR_MULT_DOSStub_973f {
  strings:
    $key_973f = { c3 57 [2] b7 4f [2] f0 4d [2] b7 5c [2] f9 50 [2] f5 5a [2] e2 51 [2] f9 1f [2] c4 }

  condition:
    any of them
}