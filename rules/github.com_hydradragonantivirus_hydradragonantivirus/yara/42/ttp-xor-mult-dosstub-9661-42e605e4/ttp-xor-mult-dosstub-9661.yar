rule TTP_XOR_MULT_DOSStub_9661 {
  strings:
    $key_9661 = { c2 09 [2] b6 11 [2] f1 13 [2] b6 02 [2] f8 0e [2] f4 04 [2] e3 0f [2] f8 41 [2] c5 }

  condition:
    any of them
}