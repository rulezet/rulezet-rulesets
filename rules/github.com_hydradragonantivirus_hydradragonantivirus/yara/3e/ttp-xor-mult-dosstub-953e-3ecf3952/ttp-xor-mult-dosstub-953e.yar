rule TTP_XOR_MULT_DOSStub_953e {
  strings:
    $key_953e = { c1 56 [2] b5 4e [2] f2 4c [2] b5 5d [2] fb 51 [2] f7 5b [2] e0 50 [2] fb 1e [2] c6 }

  condition:
    any of them
}