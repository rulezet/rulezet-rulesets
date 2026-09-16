rule TTP_XOR_MULT_DOSStub_95ee {
  strings:
    $key_95ee = { c1 86 [2] b5 9e [2] f2 9c [2] b5 8d [2] fb 81 [2] f7 8b [2] e0 80 [2] fb ce [2] c6 }

  condition:
    any of them
}