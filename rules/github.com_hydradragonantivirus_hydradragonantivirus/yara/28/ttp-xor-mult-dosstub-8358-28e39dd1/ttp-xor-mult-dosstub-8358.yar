rule TTP_XOR_MULT_DOSStub_8358 {
  strings:
    $key_8358 = { d7 30 [2] a3 28 [2] e4 2a [2] a3 3b [2] ed 37 [2] e1 3d [2] f6 36 [2] ed 78 [2] d0 }

  condition:
    any of them
}