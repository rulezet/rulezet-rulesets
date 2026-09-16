rule TTP_XOR_MULT_DOSStub_05ac {
  strings:
    $key_05ac = { 51 c4 [2] 25 dc [2] 62 de [2] 25 cf [2] 6b c3 [2] 67 c9 [2] 70 c2 [2] 6b 8c [2] 56 }

  condition:
    any of them
}