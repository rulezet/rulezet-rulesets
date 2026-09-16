rule TTP_XOR_MULT_DOSStub_a608 {
  strings:
    $key_a608 = { f2 60 [2] 86 78 [2] c1 7a [2] 86 6b [2] c8 67 [2] c4 6d [2] d3 66 [2] c8 28 [2] f5 }

  condition:
    any of them
}