rule TTP_XOR_MULT_DOSStub_9408 {
  strings:
    $key_9408 = { c0 60 [2] b4 78 [2] f3 7a [2] b4 6b [2] fa 67 [2] f6 6d [2] e1 66 [2] fa 28 [2] c7 }

  condition:
    any of them
}