rule TTP_XOR_MULT_DOSStub_9527 {
  strings:
    $key_9527 = { c1 4f [2] b5 57 [2] f2 55 [2] b5 44 [2] fb 48 [2] f7 42 [2] e0 49 [2] fb 07 [2] c6 }

  condition:
    any of them
}