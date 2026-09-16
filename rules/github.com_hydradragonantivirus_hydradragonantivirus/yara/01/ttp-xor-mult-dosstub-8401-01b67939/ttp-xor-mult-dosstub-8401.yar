rule TTP_XOR_MULT_DOSStub_8401 {
  strings:
    $key_8401 = { d0 69 [2] a4 71 [2] e3 73 [2] a4 62 [2] ea 6e [2] e6 64 [2] f1 6f [2] ea 21 [2] d7 }

  condition:
    any of them
}