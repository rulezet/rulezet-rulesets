rule TTP_XOR_MULT_DOSStub_9639 {
  strings:
    $key_9639 = { c2 51 [2] b6 49 [2] f1 4b [2] b6 5a [2] f8 56 [2] f4 5c [2] e3 57 [2] f8 19 [2] c5 }

  condition:
    any of them
}