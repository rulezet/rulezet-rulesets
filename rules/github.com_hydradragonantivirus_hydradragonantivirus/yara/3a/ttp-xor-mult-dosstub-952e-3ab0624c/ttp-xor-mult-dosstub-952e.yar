rule TTP_XOR_MULT_DOSStub_952e {
  strings:
    $key_952e = { c1 46 [2] b5 5e [2] f2 5c [2] b5 4d [2] fb 41 [2] f7 4b [2] e0 40 [2] fb 0e [2] c6 }

  condition:
    any of them
}