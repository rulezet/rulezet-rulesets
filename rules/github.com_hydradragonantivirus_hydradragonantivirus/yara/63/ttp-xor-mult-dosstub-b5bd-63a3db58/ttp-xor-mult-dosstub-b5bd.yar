rule TTP_XOR_MULT_DOSStub_b5bd {
  strings:
    $key_b5bd = { e1 d5 [2] 95 cd [2] d2 cf [2] 95 de [2] db d2 [2] d7 d8 [2] c0 d3 [2] db 9d [2] e6 }

  condition:
    any of them
}