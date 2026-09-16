rule TTP_XOR_MULT_DOSStub_a61c {
  strings:
    $key_a61c = { f2 74 [2] 86 6c [2] c1 6e [2] 86 7f [2] c8 73 [2] c4 79 [2] d3 72 [2] c8 3c [2] f5 }

  condition:
    any of them
}