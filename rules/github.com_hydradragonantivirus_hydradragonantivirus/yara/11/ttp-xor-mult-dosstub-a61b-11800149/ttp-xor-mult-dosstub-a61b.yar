rule TTP_XOR_MULT_DOSStub_a61b {
  strings:
    $key_a61b = { f2 73 [2] 86 6b [2] c1 69 [2] 86 78 [2] c8 74 [2] c4 7e [2] d3 75 [2] c8 3b [2] f5 }

  condition:
    any of them
}