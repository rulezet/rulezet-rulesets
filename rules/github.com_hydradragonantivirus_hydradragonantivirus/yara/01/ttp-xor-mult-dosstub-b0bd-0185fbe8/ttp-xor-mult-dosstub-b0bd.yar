rule TTP_XOR_MULT_DOSStub_b0bd {
  strings:
    $key_b0bd = { e4 d5 [2] 90 cd [2] d7 cf [2] 90 de [2] de d2 [2] d2 d8 [2] c5 d3 [2] de 9d [2] e3 }

  condition:
    any of them
}