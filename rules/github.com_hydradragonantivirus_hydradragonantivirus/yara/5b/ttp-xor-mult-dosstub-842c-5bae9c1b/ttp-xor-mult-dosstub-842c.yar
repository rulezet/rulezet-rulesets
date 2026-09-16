rule TTP_XOR_MULT_DOSStub_842c {
  strings:
    $key_842c = { d0 44 [2] a4 5c [2] e3 5e [2] a4 4f [2] ea 43 [2] e6 49 [2] f1 42 [2] ea 0c [2] d7 }

  condition:
    any of them
}