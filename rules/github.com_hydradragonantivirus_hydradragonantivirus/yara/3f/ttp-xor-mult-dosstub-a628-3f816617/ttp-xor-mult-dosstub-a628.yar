rule TTP_XOR_MULT_DOSStub_a628 {
  strings:
    $key_a628 = { f2 40 [2] 86 58 [2] c1 5a [2] 86 4b [2] c8 47 [2] c4 4d [2] d3 46 [2] c8 08 [2] f5 }

  condition:
    any of them
}