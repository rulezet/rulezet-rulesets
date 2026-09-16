rule TTP_XOR_MULT_DOSStub_951f {
  strings:
    $key_951f = { c1 77 [2] b5 6f [2] f2 6d [2] b5 7c [2] fb 70 [2] f7 7a [2] e0 71 [2] fb 3f [2] c6 }

  condition:
    any of them
}