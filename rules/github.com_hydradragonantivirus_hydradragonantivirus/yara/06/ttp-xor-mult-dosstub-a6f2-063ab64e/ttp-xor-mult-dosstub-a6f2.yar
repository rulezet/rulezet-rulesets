rule TTP_XOR_MULT_DOSStub_a6f2 {
  strings:
    $key_a6f2 = { f2 9a [2] 86 82 [2] c1 80 [2] 86 91 [2] c8 9d [2] c4 97 [2] d3 9c [2] c8 d2 [2] f5 }

  condition:
    any of them
}