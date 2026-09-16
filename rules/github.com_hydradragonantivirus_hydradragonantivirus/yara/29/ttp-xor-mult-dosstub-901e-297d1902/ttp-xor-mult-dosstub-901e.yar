rule TTP_XOR_MULT_DOSStub_901e {
  strings:
    $key_901e = { c4 76 [2] b0 6e [2] f7 6c [2] b0 7d [2] fe 71 [2] f2 7b [2] e5 70 [2] fe 3e [2] c3 }

  condition:
    any of them
}