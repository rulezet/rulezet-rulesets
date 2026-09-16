rule TTP_XOR_MULT_DOSStub_59a7 {
  strings:
    $key_59a7 = { 0d cf [2] 79 d7 [2] 3e d5 [2] 79 c4 [2] 37 c8 [2] 3b c2 [2] 2c c9 [2] 37 87 [2] 0a }

  condition:
    any of them
}