rule TTP_XOR_MULT_DOSStub_17ac {
  strings:
    $key_17ac = { 43 c4 [2] 37 dc [2] 70 de [2] 37 cf [2] 79 c3 [2] 75 c9 [2] 62 c2 [2] 79 8c [2] 44 }

  condition:
    any of them
}