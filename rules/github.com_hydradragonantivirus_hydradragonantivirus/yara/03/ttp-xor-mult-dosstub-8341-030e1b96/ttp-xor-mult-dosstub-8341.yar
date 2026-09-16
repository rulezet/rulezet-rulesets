rule TTP_XOR_MULT_DOSStub_8341 {
  strings:
    $key_8341 = { d7 29 [2] a3 31 [2] e4 33 [2] a3 22 [2] ed 2e [2] e1 24 [2] f6 2f [2] ed 61 [2] d0 }

  condition:
    any of them
}