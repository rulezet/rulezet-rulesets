rule TTP_XOR_MULT_DOSStub_9221 {
  strings:
    $key_9221 = { c6 49 [2] b2 51 [2] f5 53 [2] b2 42 [2] fc 4e [2] f0 44 [2] e7 4f [2] fc 01 [2] c1 }

  condition:
    any of them
}