rule TTP_XOR_MULT_DOSStub_a664 {
  strings:
    $key_a664 = { f2 0c [2] 86 14 [2] c1 16 [2] 86 07 [2] c8 0b [2] c4 01 [2] d3 0a [2] c8 44 [2] f5 }

  condition:
    any of them
}