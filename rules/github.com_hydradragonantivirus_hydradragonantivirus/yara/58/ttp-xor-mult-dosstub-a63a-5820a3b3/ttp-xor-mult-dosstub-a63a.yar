rule TTP_XOR_MULT_DOSStub_a63a {
  strings:
    $key_a63a = { f2 52 [2] 86 4a [2] c1 48 [2] 86 59 [2] c8 55 [2] c4 5f [2] d3 54 [2] c8 1a [2] f5 }

  condition:
    any of them
}