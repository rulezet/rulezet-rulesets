rule TTP_XOR_MULT_DOSStub_a753 {
  strings:
    $key_a753 = { f3 3b [2] 87 23 [2] c0 21 [2] 87 30 [2] c9 3c [2] c5 36 [2] d2 3d [2] c9 73 [2] f4 }

  condition:
    any of them
}