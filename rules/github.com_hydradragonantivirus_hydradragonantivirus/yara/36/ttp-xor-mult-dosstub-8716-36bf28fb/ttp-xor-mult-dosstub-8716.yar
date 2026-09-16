rule TTP_XOR_MULT_DOSStub_8716 {
  strings:
    $key_8716 = { d3 7e [2] a7 66 [2] e0 64 [2] a7 75 [2] e9 79 [2] e5 73 [2] f2 78 [2] e9 36 [2] d4 }

  condition:
    any of them
}