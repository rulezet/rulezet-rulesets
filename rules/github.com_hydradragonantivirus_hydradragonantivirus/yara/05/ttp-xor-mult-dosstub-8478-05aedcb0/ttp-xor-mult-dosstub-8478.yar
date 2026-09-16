rule TTP_XOR_MULT_DOSStub_8478 {
  strings:
    $key_8478 = { d0 10 [2] a4 08 [2] e3 0a [2] a4 1b [2] ea 17 [2] e6 1d [2] f1 16 [2] ea 58 [2] d7 }

  condition:
    any of them
}