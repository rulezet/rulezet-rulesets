rule TTP_XOR_MULT_DOSStub_9762 {
  strings:
    $key_9762 = { c3 0a [2] b7 12 [2] f0 10 [2] b7 01 [2] f9 0d [2] f5 07 [2] e2 0c [2] f9 42 [2] c4 }

  condition:
    any of them
}