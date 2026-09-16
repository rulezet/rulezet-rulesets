rule TTP_XOR_MULT_DOSStub_9464 {
  strings:
    $key_9464 = { c0 0c [2] b4 14 [2] f3 16 [2] b4 07 [2] fa 0b [2] f6 01 [2] e1 0a [2] fa 44 [2] c7 }

  condition:
    any of them
}