rule TTP_XOR_MULT_DOSStub_8304 {
  strings:
    $key_8304 = { d7 6c [2] a3 74 [2] e4 76 [2] a3 67 [2] ed 6b [2] e1 61 [2] f6 6a [2] ed 24 [2] d0 }

  condition:
    any of them
}