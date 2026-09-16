rule TTP_XOR_MULT_DOSStub_9405 {
  strings:
    $key_9405 = { c0 6d [2] b4 75 [2] f3 77 [2] b4 66 [2] fa 6a [2] f6 60 [2] e1 6b [2] fa 25 [2] c7 }

  condition:
    any of them
}