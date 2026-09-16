rule TTP_XOR_MULT_DOSStub_9760 {
  strings:
    $key_9760 = { c3 08 [2] b7 10 [2] f0 12 [2] b7 03 [2] f9 0f [2] f5 05 [2] e2 0e [2] f9 40 [2] c4 }

  condition:
    any of them
}