rule TTP_XOR_MULT_DOSStub_a66a {
  strings:
    $key_a66a = { f2 02 [2] 86 1a [2] c1 18 [2] 86 09 [2] c8 05 [2] c4 0f [2] d3 04 [2] c8 4a [2] f5 }

  condition:
    any of them
}