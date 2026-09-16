rule TTP_XOR_MULT_DOSStub_11ac {
  strings:
    $key_11ac = { 45 c4 [2] 31 dc [2] 76 de [2] 31 cf [2] 7f c3 [2] 73 c9 [2] 64 c2 [2] 7f 8c [2] 42 }

  condition:
    any of them
}