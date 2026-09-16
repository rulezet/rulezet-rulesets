rule TTP_XOR_MULT_DOSStub_9607 {
  strings:
    $key_9607 = { c2 6f [2] b6 77 [2] f1 75 [2] b6 64 [2] f8 68 [2] f4 62 [2] e3 69 [2] f8 27 [2] c5 }

  condition:
    any of them
}