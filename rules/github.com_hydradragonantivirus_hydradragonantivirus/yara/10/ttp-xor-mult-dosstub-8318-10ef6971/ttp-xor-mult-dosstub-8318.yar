rule TTP_XOR_MULT_DOSStub_8318 {
  strings:
    $key_8318 = { d7 70 [2] a3 68 [2] e4 6a [2] a3 7b [2] ed 77 [2] e1 7d [2] f6 76 [2] ed 38 [2] d0 }

  condition:
    any of them
}