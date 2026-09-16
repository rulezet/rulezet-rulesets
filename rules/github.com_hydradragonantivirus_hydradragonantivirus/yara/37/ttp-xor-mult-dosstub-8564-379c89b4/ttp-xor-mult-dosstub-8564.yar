rule TTP_XOR_MULT_DOSStub_8564 {
  strings:
    $key_8564 = { d1 0c [2] a5 14 [2] e2 16 [2] a5 07 [2] eb 0b [2] e7 01 [2] f0 0a [2] eb 44 [2] d6 }

  condition:
    any of them
}