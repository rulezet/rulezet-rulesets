rule TTP_XOR_MULT_DOSStub_8464 {
  strings:
    $key_8464 = { d0 0c [2] a4 14 [2] e3 16 [2] a4 07 [2] ea 0b [2] e6 01 [2] f1 0a [2] ea 44 [2] d7 }

  condition:
    any of them
}