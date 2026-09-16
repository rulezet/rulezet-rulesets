rule TTP_XOR_MULT_DOSStub_842e {
  strings:
    $key_842e = { d0 46 [2] a4 5e [2] e3 5c [2] a4 4d [2] ea 41 [2] e6 4b [2] f1 40 [2] ea 0e [2] d7 }

  condition:
    any of them
}