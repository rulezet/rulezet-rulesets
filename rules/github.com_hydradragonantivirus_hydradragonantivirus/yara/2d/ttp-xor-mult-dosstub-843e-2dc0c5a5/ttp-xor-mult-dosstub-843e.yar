rule TTP_XOR_MULT_DOSStub_843e {
  strings:
    $key_843e = { d0 56 [2] a4 4e [2] e3 4c [2] a4 5d [2] ea 51 [2] e6 5b [2] f1 50 [2] ea 1e [2] d7 }

  condition:
    any of them
}