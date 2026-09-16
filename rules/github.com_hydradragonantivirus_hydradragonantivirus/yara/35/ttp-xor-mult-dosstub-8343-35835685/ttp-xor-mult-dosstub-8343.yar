rule TTP_XOR_MULT_DOSStub_8343 {
  strings:
    $key_8343 = { d7 2b [2] a3 33 [2] e4 31 [2] a3 20 [2] ed 2c [2] e1 26 [2] f6 2d [2] ed 63 [2] d0 }

  condition:
    any of them
}