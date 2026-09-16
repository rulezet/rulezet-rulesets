rule TTP_XOR_MULT_DOSStub_967c {
  strings:
    $key_967c = { c2 14 [2] b6 0c [2] f1 0e [2] b6 1f [2] f8 13 [2] f4 19 [2] e3 12 [2] f8 5c [2] c5 }

  condition:
    any of them
}