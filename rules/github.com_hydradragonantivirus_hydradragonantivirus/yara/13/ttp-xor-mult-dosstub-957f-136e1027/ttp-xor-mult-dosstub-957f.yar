rule TTP_XOR_MULT_DOSStub_957f {
  strings:
    $key_957f = { c1 17 [2] b5 0f [2] f2 0d [2] b5 1c [2] fb 10 [2] f7 1a [2] e0 11 [2] fb 5f [2] c6 }

  condition:
    any of them
}