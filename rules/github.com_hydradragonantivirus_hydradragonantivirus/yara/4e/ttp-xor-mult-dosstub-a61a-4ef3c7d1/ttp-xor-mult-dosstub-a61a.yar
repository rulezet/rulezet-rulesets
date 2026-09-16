rule TTP_XOR_MULT_DOSStub_a61a {
  strings:
    $key_a61a = { f2 72 [2] 86 6a [2] c1 68 [2] 86 79 [2] c8 75 [2] c4 7f [2] d3 74 [2] c8 3a [2] f5 }

  condition:
    any of them
}