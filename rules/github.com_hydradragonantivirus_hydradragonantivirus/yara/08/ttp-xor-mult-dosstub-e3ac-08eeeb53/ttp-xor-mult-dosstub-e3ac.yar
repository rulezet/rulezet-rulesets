rule TTP_XOR_MULT_DOSStub_e3ac {
  strings:
    $key_e3ac = { b7 c4 [2] c3 dc [2] 84 de [2] c3 cf [2] 8d c3 [2] 81 c9 [2] 96 c2 [2] 8d 8c [2] b0 }

  condition:
    any of them
}