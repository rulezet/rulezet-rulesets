rule TTP_XOR_MULT_DOSStub_e2ac {
  strings:
    $key_e2ac = { b6 c4 [2] c2 dc [2] 85 de [2] c2 cf [2] 8c c3 [2] 80 c9 [2] 97 c2 [2] 8c 8c [2] b1 }

  condition:
    any of them
}