rule TTP_XOR_MULT_DOSStub_02ac {
  strings:
    $key_02ac = { 56 c4 [2] 22 dc [2] 65 de [2] 22 cf [2] 6c c3 [2] 60 c9 [2] 77 c2 [2] 6c 8c [2] 51 }

  condition:
    any of them
}