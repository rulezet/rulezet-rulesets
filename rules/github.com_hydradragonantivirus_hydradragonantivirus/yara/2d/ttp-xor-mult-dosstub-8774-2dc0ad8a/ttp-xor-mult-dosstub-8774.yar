rule TTP_XOR_MULT_DOSStub_8774 {
  strings:
    $key_8774 = { d3 1c [2] a7 04 [2] e0 06 [2] a7 17 [2] e9 1b [2] e5 11 [2] f2 1a [2] e9 54 [2] d4 }

  condition:
    any of them
}