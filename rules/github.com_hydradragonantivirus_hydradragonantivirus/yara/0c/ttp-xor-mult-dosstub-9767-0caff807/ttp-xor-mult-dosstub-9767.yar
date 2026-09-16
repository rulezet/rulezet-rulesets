rule TTP_XOR_MULT_DOSStub_9767 {
  strings:
    $key_9767 = { c3 0f [2] b7 17 [2] f0 15 [2] b7 04 [2] f9 08 [2] f5 02 [2] e2 09 [2] f9 47 [2] c4 }

  condition:
    any of them
}