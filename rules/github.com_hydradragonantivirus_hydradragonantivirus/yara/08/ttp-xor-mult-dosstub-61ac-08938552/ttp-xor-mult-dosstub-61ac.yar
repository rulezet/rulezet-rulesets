rule TTP_XOR_MULT_DOSStub_61ac {
  strings:
    $key_61ac = { 35 c4 [2] 41 dc [2] 06 de [2] 41 cf [2] 0f c3 [2] 03 c9 [2] 14 c2 [2] 0f 8c [2] 32 }

  condition:
    any of them
}