rule TTP_XOR_MULT_DOSStub_9773 {
  strings:
    $key_9773 = { c3 1b [2] b7 03 [2] f0 01 [2] b7 10 [2] f9 1c [2] f5 16 [2] e2 1d [2] f9 53 [2] c4 }

  condition:
    any of them
}