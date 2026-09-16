rule TTP_XOR_MULT_DOSStub_8713 {
  strings:
    $key_8713 = { d3 7b [2] a7 63 [2] e0 61 [2] a7 70 [2] e9 7c [2] e5 76 [2] f2 7d [2] e9 33 [2] d4 }

  condition:
    any of them
}