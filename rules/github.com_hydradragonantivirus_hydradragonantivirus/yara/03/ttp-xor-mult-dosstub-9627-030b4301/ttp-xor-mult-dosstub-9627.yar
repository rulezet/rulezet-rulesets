rule TTP_XOR_MULT_DOSStub_9627 {
  strings:
    $key_9627 = { c2 4f [2] b6 57 [2] f1 55 [2] b6 44 [2] f8 48 [2] f4 42 [2] e3 49 [2] f8 07 [2] c5 }

  condition:
    any of them
}