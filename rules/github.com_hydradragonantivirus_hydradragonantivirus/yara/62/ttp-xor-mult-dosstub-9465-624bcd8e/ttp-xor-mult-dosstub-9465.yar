rule TTP_XOR_MULT_DOSStub_9465 {
  strings:
    $key_9465 = { c0 0d [2] b4 15 [2] f3 17 [2] b4 06 [2] fa 0a [2] f6 00 [2] e1 0b [2] fa 45 [2] c7 }

  condition:
    any of them
}