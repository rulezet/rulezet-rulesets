rule TTP_XOR_MULT_DOSStub_8425 {
  strings:
    $key_8425 = { d0 4d [2] a4 55 [2] e3 57 [2] a4 46 [2] ea 4a [2] e6 40 [2] f1 4b [2] ea 05 [2] d7 }

  condition:
    any of them
}