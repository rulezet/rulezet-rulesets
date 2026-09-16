rule TTP_XOR_MULT_DOSStub_a60a {
  strings:
    $key_a60a = { f2 62 [2] 86 7a [2] c1 78 [2] 86 69 [2] c8 65 [2] c4 6f [2] d3 64 [2] c8 2a [2] f5 }

  condition:
    any of them
}