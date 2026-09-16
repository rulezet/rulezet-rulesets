rule TTP_XOR_MULT_DOSStub_a63f {
  strings:
    $key_a63f = { f2 57 [2] 86 4f [2] c1 4d [2] 86 5c [2] c8 50 [2] c4 5a [2] d3 51 [2] c8 1f [2] f5 }

  condition:
    any of them
}