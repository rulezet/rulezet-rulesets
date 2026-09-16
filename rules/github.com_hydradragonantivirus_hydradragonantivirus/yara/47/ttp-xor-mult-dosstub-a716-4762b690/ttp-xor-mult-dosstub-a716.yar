rule TTP_XOR_MULT_DOSStub_a716 {
  strings:
    $key_a716 = { f3 7e [2] 87 66 [2] c0 64 [2] 87 75 [2] c9 79 [2] c5 73 [2] d2 78 [2] c9 36 [2] f4 }

  condition:
    any of them
}