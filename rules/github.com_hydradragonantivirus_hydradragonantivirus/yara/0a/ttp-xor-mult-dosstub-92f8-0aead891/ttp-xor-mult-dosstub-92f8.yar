rule TTP_XOR_MULT_DOSStub_92f8 {
  strings:
    $key_92f8 = { c6 90 [2] b2 88 [2] f5 8a [2] b2 9b [2] fc 97 [2] f0 9d [2] e7 96 [2] fc d8 [2] c1 }

  condition:
    any of them
}