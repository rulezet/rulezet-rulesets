rule TTP_XOR_MULT_DOSStub_a66d {
  strings:
    $key_a66d = { f2 05 [2] 86 1d [2] c1 1f [2] 86 0e [2] c8 02 [2] c4 08 [2] d3 03 [2] c8 4d [2] f5 }

  condition:
    any of them
}