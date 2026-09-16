rule TTP_XOR_MULT_DOSStub_8753 {
  strings:
    $key_8753 = { d3 3b [2] a7 23 [2] e0 21 [2] a7 30 [2] e9 3c [2] e5 36 [2] f2 3d [2] e9 73 [2] d4 }

  condition:
    any of them
}