rule TTP_XOR_MULT_DOSStub_a629 {
  strings:
    $key_a629 = { f2 41 [2] 86 59 [2] c1 5b [2] 86 4a [2] c8 46 [2] c4 4c [2] d3 47 [2] c8 09 [2] f5 }

  condition:
    any of them
}