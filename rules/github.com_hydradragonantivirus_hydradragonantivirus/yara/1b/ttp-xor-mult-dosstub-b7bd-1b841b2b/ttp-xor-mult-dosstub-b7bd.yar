rule TTP_XOR_MULT_DOSStub_b7bd {
  strings:
    $key_b7bd = { e3 d5 [2] 97 cd [2] d0 cf [2] 97 de [2] d9 d2 [2] d5 d8 [2] c2 d3 [2] d9 9d [2] e4 }

  condition:
    any of them
}