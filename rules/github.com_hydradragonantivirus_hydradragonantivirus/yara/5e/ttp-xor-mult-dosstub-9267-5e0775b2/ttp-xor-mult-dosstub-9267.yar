rule TTP_XOR_MULT_DOSStub_9267 {
  strings:
    $key_9267 = { c6 0f [2] b2 17 [2] f5 15 [2] b2 04 [2] fc 08 [2] f0 02 [2] e7 09 [2] fc 47 [2] c1 }

  condition:
    any of them
}