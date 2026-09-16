rule TTP_XOR_MULT_DOSStub_a658 {
  strings:
    $key_a658 = { f2 30 [2] 86 28 [2] c1 2a [2] 86 3b [2] c8 37 [2] c4 3d [2] d3 36 [2] c8 78 [2] f5 }

  condition:
    any of them
}