rule TTP_XOR_MULT_DOSStub_a66e {
  strings:
    $key_a66e = { f2 06 [2] 86 1e [2] c1 1c [2] 86 0d [2] c8 01 [2] c4 0b [2] d3 00 [2] c8 4e [2] f5 }

  condition:
    any of them
}