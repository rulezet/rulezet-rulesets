rule TTP_XOR_MULT_DOSStub_a66c {
  strings:
    $key_a66c = { f2 04 [2] 86 1c [2] c1 1e [2] 86 0f [2] c8 03 [2] c4 09 [2] d3 02 [2] c8 4c [2] f5 }

  condition:
    any of them
}