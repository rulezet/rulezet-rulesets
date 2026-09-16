rule TTP_XOR_MULT_DOSStub_35ac {
  strings:
    $key_35ac = { 61 c4 [2] 15 dc [2] 52 de [2] 15 cf [2] 5b c3 [2] 57 c9 [2] 40 c2 [2] 5b 8c [2] 66 }

  condition:
    any of them
}