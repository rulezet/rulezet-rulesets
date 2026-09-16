rule TTP_XOR_MULT_DOSStub_a63c {
  strings:
    $key_a63c = { f2 54 [2] 86 4c [2] c1 4e [2] 86 5f [2] c8 53 [2] c4 59 [2] d3 52 [2] c8 1c [2] f5 }

  condition:
    any of them
}