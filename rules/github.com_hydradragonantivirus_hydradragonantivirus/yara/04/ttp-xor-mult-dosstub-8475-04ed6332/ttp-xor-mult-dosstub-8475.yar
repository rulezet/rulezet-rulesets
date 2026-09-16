rule TTP_XOR_MULT_DOSStub_8475 {
  strings:
    $key_8475 = { d0 1d [2] a4 05 [2] e3 07 [2] a4 16 [2] ea 1a [2] e6 10 [2] f1 1b [2] ea 55 [2] d7 }

  condition:
    any of them
}