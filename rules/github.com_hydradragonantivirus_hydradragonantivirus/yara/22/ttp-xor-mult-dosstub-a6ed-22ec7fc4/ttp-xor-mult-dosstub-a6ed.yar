rule TTP_XOR_MULT_DOSStub_a6ed {
  strings:
    $key_a6ed = { f2 85 [2] 86 9d [2] c1 9f [2] 86 8e [2] c8 82 [2] c4 88 [2] d3 83 [2] c8 cd [2] f5 }

  condition:
    any of them
}