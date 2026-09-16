rule TTP_XOR_MULT_DOSStub_9557 {
  strings:
    $key_9557 = { c1 3f [2] b5 27 [2] f2 25 [2] b5 34 [2] fb 38 [2] f7 32 [2] e0 39 [2] fb 77 [2] c6 }

  condition:
    any of them
}