rule TTP_XOR_MULT_DOSStub_9472 {
  strings:
    $key_9472 = { c0 1a [2] b4 02 [2] f3 00 [2] b4 11 [2] fa 1d [2] f6 17 [2] e1 1c [2] fa 52 [2] c7 }

  condition:
    any of them
}