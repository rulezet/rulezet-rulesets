rule TTP_XOR_MULT_DOSStub_8418 {
  strings:
    $key_8418 = { d0 70 [2] a4 68 [2] e3 6a [2] a4 7b [2] ea 77 [2] e6 7d [2] f1 76 [2] ea 38 [2] d7 }

  condition:
    any of them
}