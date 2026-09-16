rule TTP_XOR_MULT_DOSStub_95fa {
  strings:
    $key_95fa = { c1 92 [2] b5 8a [2] f2 88 [2] b5 99 [2] fb 95 [2] f7 9f [2] e0 94 [2] fb da [2] c6 }

  condition:
    any of them
}