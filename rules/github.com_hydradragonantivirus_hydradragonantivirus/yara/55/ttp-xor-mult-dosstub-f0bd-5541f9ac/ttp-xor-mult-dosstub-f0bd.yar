rule TTP_XOR_MULT_DOSStub_f0bd {
  strings:
    $key_f0bd = { a4 d5 [2] d0 cd [2] 97 cf [2] d0 de [2] 9e d2 [2] 92 d8 [2] 85 d3 [2] 9e 9d [2] a3 }

  condition:
    any of them
}