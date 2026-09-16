rule TTP_XOR_MULT_DOSStub_8579 {
  strings:
    $key_8579 = { d1 11 [2] a5 09 [2] e2 0b [2] a5 1a [2] eb 16 [2] e7 1c [2] f0 17 [2] eb 59 [2] d6 }

  condition:
    any of them
}