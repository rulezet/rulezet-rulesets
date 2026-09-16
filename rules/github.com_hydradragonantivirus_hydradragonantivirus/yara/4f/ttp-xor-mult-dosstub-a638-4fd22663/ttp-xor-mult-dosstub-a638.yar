rule TTP_XOR_MULT_DOSStub_a638 {
  strings:
    $key_a638 = { f2 50 [2] 86 48 [2] c1 4a [2] 86 5b [2] c8 57 [2] c4 5d [2] d3 56 [2] c8 18 [2] f5 }

  condition:
    any of them
}