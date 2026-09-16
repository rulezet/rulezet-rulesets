rule TTP_XOR_MULT_DOSStub_841e {
  strings:
    $key_841e = { d0 76 [2] a4 6e [2] e3 6c [2] a4 7d [2] ea 71 [2] e6 7b [2] f1 70 [2] ea 3e [2] d7 }

  condition:
    any of them
}