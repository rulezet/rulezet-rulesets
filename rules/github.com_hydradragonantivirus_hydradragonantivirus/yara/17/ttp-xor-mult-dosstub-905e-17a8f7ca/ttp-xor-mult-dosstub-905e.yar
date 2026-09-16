rule TTP_XOR_MULT_DOSStub_905e {
  strings:
    $key_905e = { c4 36 [2] b0 2e [2] f7 2c [2] b0 3d [2] fe 31 [2] f2 3b [2] e5 30 [2] fe 7e [2] c3 }

  condition:
    any of them
}