rule TTP_XOR_MULT_DOSStub_8417 {
  strings:
    $key_8417 = { d0 7f [2] a4 67 [2] e3 65 [2] a4 74 [2] ea 78 [2] e6 72 [2] f1 79 [2] ea 37 [2] d7 }

  condition:
    any of them
}