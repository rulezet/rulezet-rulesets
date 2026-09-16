rule TTP_XOR_MULT_DOSStub_8458 {
  strings:
    $key_8458 = { d0 30 [2] a4 28 [2] e3 2a [2] a4 3b [2] ea 37 [2] e6 3d [2] f1 36 [2] ea 78 [2] d7 }

  condition:
    any of them
}