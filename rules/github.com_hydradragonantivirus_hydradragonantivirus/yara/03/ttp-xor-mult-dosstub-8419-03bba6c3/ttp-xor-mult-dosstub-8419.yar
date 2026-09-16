rule TTP_XOR_MULT_DOSStub_8419 {
  strings:
    $key_8419 = { d0 71 [2] a4 69 [2] e3 6b [2] a4 7a [2] ea 76 [2] e6 7c [2] f1 77 [2] ea 39 [2] d7 }

  condition:
    any of them
}