rule TTP_XOR_MULT_DOSStub_8719 {
  strings:
    $key_8719 = { d3 71 [2] a7 69 [2] e0 6b [2] a7 7a [2] e9 76 [2] e5 7c [2] f2 77 [2] e9 39 [2] d4 }

  condition:
    any of them
}