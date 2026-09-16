rule TTP_XOR_MULT_DOSStub_950e {
  strings:
    $key_950e = { c1 66 [2] b5 7e [2] f2 7c [2] b5 6d [2] fb 61 [2] f7 6b [2] e0 60 [2] fb 2e [2] c6 }

  condition:
    any of them
}