rule TTP_XOR_MULT_DOSStub_844c {
  strings:
    $key_844c = { d0 24 [2] a4 3c [2] e3 3e [2] a4 2f [2] ea 23 [2] e6 29 [2] f1 22 [2] ea 6c [2] d7 }

  condition:
    any of them
}