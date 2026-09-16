rule TTP_XOR_MULT_DOSStub_8308 {
  strings:
    $key_8308 = { d7 60 [2] a3 78 [2] e4 7a [2] a3 6b [2] ed 67 [2] e1 6d [2] f6 66 [2] ed 28 [2] d0 }

  condition:
    any of them
}