rule TTP_XOR_MULT_DOSStub_a669 {
  strings:
    $key_a669 = { f2 01 [2] 86 19 [2] c1 1b [2] 86 0a [2] c8 06 [2] c4 0c [2] d3 07 [2] c8 49 [2] f5 }

  condition:
    any of them
}