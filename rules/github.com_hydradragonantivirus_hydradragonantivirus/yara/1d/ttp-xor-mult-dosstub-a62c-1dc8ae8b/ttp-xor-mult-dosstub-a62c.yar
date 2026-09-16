rule TTP_XOR_MULT_DOSStub_a62c {
  strings:
    $key_a62c = { f2 44 [2] 86 5c [2] c1 5e [2] 86 4f [2] c8 43 [2] c4 49 [2] d3 42 [2] c8 0c [2] f5 }

  condition:
    any of them
}