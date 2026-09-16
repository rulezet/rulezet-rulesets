rule TTP_XOR_MULT_DOSStub_92f9 {
  strings:
    $key_92f9 = { c6 91 [2] b2 89 [2] f5 8b [2] b2 9a [2] fc 96 [2] f0 9c [2] e7 97 [2] fc d9 [2] c1 }

  condition:
    any of them
}