rule TTP_XOR_MULT_DOSStub_a653 {
  strings:
    $key_a653 = { f2 3b [2] 86 23 [2] c1 21 [2] 86 30 [2] c8 3c [2] c4 36 [2] d3 3d [2] c8 73 [2] f5 }

  condition:
    any of them
}