rule TTP_XOR_MULT_DOSStub_952f {
  strings:
    $key_952f = { c1 47 [2] b5 5f [2] f2 5d [2] b5 4c [2] fb 40 [2] f7 4a [2] e0 41 [2] fb 0f [2] c6 }

  condition:
    any of them
}