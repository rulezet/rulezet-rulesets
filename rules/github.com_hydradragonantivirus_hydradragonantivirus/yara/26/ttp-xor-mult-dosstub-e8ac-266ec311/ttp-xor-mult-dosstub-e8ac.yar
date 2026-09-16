rule TTP_XOR_MULT_DOSStub_e8ac {
  strings:
    $key_e8ac = { bc c4 [2] c8 dc [2] 8f de [2] c8 cf [2] 86 c3 [2] 8a c9 [2] 9d c2 [2] 86 8c [2] bb }

  condition:
    any of them
}