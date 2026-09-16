rule TTP_XOR_MULT_DOSStub_8412 {
  strings:
    $key_8412 = { d0 7a [2] a4 62 [2] e3 60 [2] a4 71 [2] ea 7d [2] e6 77 [2] f1 7c [2] ea 32 [2] d7 }

  condition:
    any of them
}