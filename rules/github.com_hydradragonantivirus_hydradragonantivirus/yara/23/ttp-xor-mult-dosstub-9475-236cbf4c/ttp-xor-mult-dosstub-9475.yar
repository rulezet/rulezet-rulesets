rule TTP_XOR_MULT_DOSStub_9475 {
  strings:
    $key_9475 = { c0 1d [2] b4 05 [2] f3 07 [2] b4 16 [2] fa 1a [2] f6 10 [2] e1 1b [2] fa 55 [2] c7 }

  condition:
    any of them
}