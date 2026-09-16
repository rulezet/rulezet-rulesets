rule TTP_XOR_MULT_DOSStub_8314 {
  strings:
    $key_8314 = { d7 7c [2] a3 64 [2] e4 66 [2] a3 77 [2] ed 7b [2] e1 71 [2] f6 7a [2] ed 34 [2] d0 }

  condition:
    any of them
}