rule TTP_XOR_MULT_DOSStub_8778 {
  strings:
    $key_8778 = { d3 10 [2] a7 08 [2] e0 0a [2] a7 1b [2] e9 17 [2] e5 1d [2] f2 16 [2] e9 58 [2] d4 }

  condition:
    any of them
}