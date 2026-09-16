rule TTP_XOR_MULT_DOSStub_9761 {
  strings:
    $key_9761 = { c3 09 [2] b7 11 [2] f0 13 [2] b7 02 [2] f9 0e [2] f5 04 [2] e2 0f [2] f9 41 [2] c4 }

  condition:
    any of them
}