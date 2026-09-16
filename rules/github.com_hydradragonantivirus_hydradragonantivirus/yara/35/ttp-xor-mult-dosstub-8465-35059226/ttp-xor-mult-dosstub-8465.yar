rule TTP_XOR_MULT_DOSStub_8465 {
  strings:
    $key_8465 = { d0 0d [2] a4 15 [2] e3 17 [2] a4 06 [2] ea 0a [2] e6 00 [2] f1 0b [2] ea 45 [2] d7 }

  condition:
    any of them
}