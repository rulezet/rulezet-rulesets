rule TTP_XOR_MULT_DOSStub_8402 {
  strings:
    $key_8402 = { d0 6a [2] a4 72 [2] e3 70 [2] a4 61 [2] ea 6d [2] e6 67 [2] f1 6c [2] ea 22 [2] d7 }

  condition:
    any of them
}