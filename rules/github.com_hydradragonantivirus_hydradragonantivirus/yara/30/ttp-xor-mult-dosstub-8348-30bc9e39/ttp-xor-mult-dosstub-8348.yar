rule TTP_XOR_MULT_DOSStub_8348 {
  strings:
    $key_8348 = { d7 20 [2] a3 38 [2] e4 3a [2] a3 2b [2] ed 27 [2] e1 2d [2] f6 26 [2] ed 68 [2] d0 }

  condition:
    any of them
}