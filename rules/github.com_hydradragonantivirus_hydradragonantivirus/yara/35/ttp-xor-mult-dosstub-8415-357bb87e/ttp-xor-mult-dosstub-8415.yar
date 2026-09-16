rule TTP_XOR_MULT_DOSStub_8415 {
  strings:
    $key_8415 = { d0 7d [2] a4 65 [2] e3 67 [2] a4 76 [2] ea 7a [2] e6 70 [2] f1 7b [2] ea 35 [2] d7 }

  condition:
    any of them
}