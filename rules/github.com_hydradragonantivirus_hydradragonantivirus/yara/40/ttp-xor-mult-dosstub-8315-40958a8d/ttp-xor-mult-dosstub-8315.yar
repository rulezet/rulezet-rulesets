rule TTP_XOR_MULT_DOSStub_8315 {
  strings:
    $key_8315 = { d7 7d [2] a3 65 [2] e4 67 [2] a3 76 [2] ed 7a [2] e1 70 [2] f6 7b [2] ed 35 [2] d0 }

  condition:
    any of them
}