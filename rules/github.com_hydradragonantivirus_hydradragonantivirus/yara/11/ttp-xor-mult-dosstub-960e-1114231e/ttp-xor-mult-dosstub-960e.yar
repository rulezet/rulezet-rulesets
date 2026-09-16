rule TTP_XOR_MULT_DOSStub_960e {
  strings:
    $key_960e = { c2 66 [2] b6 7e [2] f1 7c [2] b6 6d [2] f8 61 [2] f4 6b [2] e3 60 [2] f8 2e [2] c5 }

  condition:
    any of them
}