rule TTP_XOR_MULT_DOSStub_8347 {
  strings:
    $key_8347 = { d7 2f [2] a3 37 [2] e4 35 [2] a3 24 [2] ed 28 [2] e1 22 [2] f6 29 [2] ed 67 [2] d0 }

  condition:
    any of them
}