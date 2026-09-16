rule TTP_XOR_MULT_DOSStub_8408 {
  strings:
    $key_8408 = { d0 60 [2] a4 78 [2] e3 7a [2] a4 6b [2] ea 67 [2] e6 6d [2] f1 66 [2] ea 28 [2] d7 }

  condition:
    any of them
}