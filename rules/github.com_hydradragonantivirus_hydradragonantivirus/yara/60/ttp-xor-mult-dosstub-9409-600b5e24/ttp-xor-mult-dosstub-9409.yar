rule TTP_XOR_MULT_DOSStub_9409 {
  strings:
    $key_9409 = { c0 61 [2] b4 79 [2] f3 7b [2] b4 6a [2] fa 66 [2] f6 6c [2] e1 67 [2] fa 29 [2] c7 }

  condition:
    any of them
}