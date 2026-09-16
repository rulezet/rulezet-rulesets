rule TTP_XOR_MULT_DOSStub_8377 {
  strings:
    $key_8377 = { d7 1f [2] a3 07 [2] e4 05 [2] a3 14 [2] ed 18 [2] e1 12 [2] f6 19 [2] ed 57 [2] d0 }

  condition:
    any of them
}