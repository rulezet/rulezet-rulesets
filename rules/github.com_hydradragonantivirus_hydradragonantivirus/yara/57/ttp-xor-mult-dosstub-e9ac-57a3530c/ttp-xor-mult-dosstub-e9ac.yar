rule TTP_XOR_MULT_DOSStub_e9ac {
  strings:
    $key_e9ac = { bd c4 [2] c9 dc [2] 8e de [2] c9 cf [2] 87 c3 [2] 8b c9 [2] 9c c2 [2] 87 8c [2] ba }

  condition:
    any of them
}