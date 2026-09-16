rule TTP_XOR_MULT_DOSStub_9444 {
  strings:
    $key_9444 = { c0 2c [2] b4 34 [2] f3 36 [2] b4 27 [2] fa 2b [2] f6 21 [2] e1 2a [2] fa 64 [2] c7 }

  condition:
    any of them
}