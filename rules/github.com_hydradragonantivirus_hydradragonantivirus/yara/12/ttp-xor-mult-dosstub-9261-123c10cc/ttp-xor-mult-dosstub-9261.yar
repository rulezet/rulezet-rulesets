rule TTP_XOR_MULT_DOSStub_9261 {
  strings:
    $key_9261 = { c6 09 [2] b2 11 [2] f5 13 [2] b2 02 [2] fc 0e [2] f0 04 [2] e7 0f [2] fc 41 [2] c1 }

  condition:
    any of them
}