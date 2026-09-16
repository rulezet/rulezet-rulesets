rule TTP_XOR_MULT_DOSStub_845b {
  strings:
    $key_845b = { d0 33 [2] a4 2b [2] e3 29 [2] a4 38 [2] ea 34 [2] e6 3e [2] f1 35 [2] ea 7b [2] d7 }

  condition:
    any of them
}