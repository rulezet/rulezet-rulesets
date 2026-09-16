rule TTP_XOR_MULT_DOSStub_f3ac {
  strings:
    $key_f3ac = { a7 c4 [2] d3 dc [2] 94 de [2] d3 cf [2] 9d c3 [2] 91 c9 [2] 86 c2 [2] 9d 8c [2] a0 }

  condition:
    any of them
}