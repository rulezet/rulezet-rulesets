rule TTP_XOR_MULT_DOSStub_8453 {
  strings:
    $key_8453 = { d0 3b [2] a4 23 [2] e3 21 [2] a4 30 [2] ea 3c [2] e6 36 [2] f1 3d [2] ea 73 [2] d7 }

  condition:
    any of them
}