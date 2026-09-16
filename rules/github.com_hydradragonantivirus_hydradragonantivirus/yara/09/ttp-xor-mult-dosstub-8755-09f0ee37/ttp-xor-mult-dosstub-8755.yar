rule TTP_XOR_MULT_DOSStub_8755 {
  strings:
    $key_8755 = { d3 3d [2] a7 25 [2] e0 27 [2] a7 36 [2] e9 3a [2] e5 30 [2] f2 3b [2] e9 75 [2] d4 }

  condition:
    any of them
}