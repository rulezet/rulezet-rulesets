rule TTP_XOR_MULT_DOSStub_a61f {
  strings:
    $key_a61f = { f2 77 [2] 86 6f [2] c1 6d [2] 86 7c [2] c8 70 [2] c4 7a [2] d3 71 [2] c8 3f [2] f5 }

  condition:
    any of them
}