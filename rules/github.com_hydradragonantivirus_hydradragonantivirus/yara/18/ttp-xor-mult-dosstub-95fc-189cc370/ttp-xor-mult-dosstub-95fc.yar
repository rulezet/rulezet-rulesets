rule TTP_XOR_MULT_DOSStub_95fc {
  strings:
    $key_95fc = { c1 94 [2] b5 8c [2] f2 8e [2] b5 9f [2] fb 93 [2] f7 99 [2] e0 92 [2] fb dc [2] c6 }

  condition:
    any of them
}