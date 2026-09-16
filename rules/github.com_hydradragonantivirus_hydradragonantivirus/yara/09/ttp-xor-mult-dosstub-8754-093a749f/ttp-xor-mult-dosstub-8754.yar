rule TTP_XOR_MULT_DOSStub_8754 {
  strings:
    $key_8754 = { d3 3c [2] a7 24 [2] e0 26 [2] a7 37 [2] e9 3b [2] e5 31 [2] f2 3a [2] e9 74 [2] d4 }

  condition:
    any of them
}