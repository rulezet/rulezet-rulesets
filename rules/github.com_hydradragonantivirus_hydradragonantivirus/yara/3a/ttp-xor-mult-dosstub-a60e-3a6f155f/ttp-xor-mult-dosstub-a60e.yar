rule TTP_XOR_MULT_DOSStub_a60e {
  strings:
    $key_a60e = { f2 66 [2] 86 7e [2] c1 7c [2] 86 6d [2] c8 61 [2] c4 6b [2] d3 60 [2] c8 2e [2] f5 }

  condition:
    any of them
}