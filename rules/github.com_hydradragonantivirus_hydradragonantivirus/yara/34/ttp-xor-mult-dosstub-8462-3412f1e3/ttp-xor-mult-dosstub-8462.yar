rule TTP_XOR_MULT_DOSStub_8462 {
  strings:
    $key_8462 = { d0 0a [2] a4 12 [2] e3 10 [2] a4 01 [2] ea 0d [2] e6 07 [2] f1 0c [2] ea 42 [2] d7 }

  condition:
    any of them
}