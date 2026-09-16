rule TTP_XOR_MULT_DOSStub_8379 {
  strings:
    $key_8379 = { d7 11 [2] a3 09 [2] e4 0b [2] a3 1a [2] ed 16 [2] e1 1c [2] f6 17 [2] ed 59 [2] d0 }

  condition:
    any of them
}