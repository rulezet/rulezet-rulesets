rule TTP_XOR_MULT_DOSStub_9435 {
  strings:
    $key_9435 = { c0 5d [2] b4 45 [2] f3 47 [2] b4 56 [2] fa 5a [2] f6 50 [2] e1 5b [2] fa 15 [2] c7 }

  condition:
    any of them
}