rule TTP_XOR_MULT_DOSStub_9462 {
  strings:
    $key_9462 = { c0 0a [2] b4 12 [2] f3 10 [2] b4 01 [2] fa 0d [2] f6 07 [2] e1 0c [2] fa 42 [2] c7 }

  condition:
    any of them
}