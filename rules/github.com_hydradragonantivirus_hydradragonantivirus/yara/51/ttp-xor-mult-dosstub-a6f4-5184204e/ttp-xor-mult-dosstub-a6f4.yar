rule TTP_XOR_MULT_DOSStub_a6f4 {
  strings:
    $key_a6f4 = { f2 9c [2] 86 84 [2] c1 86 [2] 86 97 [2] c8 9b [2] c4 91 [2] d3 9a [2] c8 d4 [2] f5 }

  condition:
    any of them
}