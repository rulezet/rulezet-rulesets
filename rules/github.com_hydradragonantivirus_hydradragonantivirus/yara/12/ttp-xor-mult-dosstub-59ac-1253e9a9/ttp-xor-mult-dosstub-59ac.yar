rule TTP_XOR_MULT_DOSStub_59ac {
  strings:
    $key_59ac = { 0d c4 [2] 79 dc [2] 3e de [2] 79 cf [2] 37 c3 [2] 3b c9 [2] 2c c2 [2] 37 8c [2] 0a }

  condition:
    any of them
}