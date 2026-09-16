rule TTP_XOR_MULT_DOSStub_9449 {
  strings:
    $key_9449 = { c0 21 [2] b4 39 [2] f3 3b [2] b4 2a [2] fa 26 [2] f6 2c [2] e1 27 [2] fa 69 [2] c7 }

  condition:
    any of them
}