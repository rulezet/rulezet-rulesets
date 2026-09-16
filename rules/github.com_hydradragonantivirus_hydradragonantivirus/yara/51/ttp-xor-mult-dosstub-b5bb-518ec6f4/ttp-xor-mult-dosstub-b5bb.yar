rule TTP_XOR_MULT_DOSStub_b5bb {
  strings:
    $key_b5bb = { e1 d3 [2] 95 cb [2] d2 c9 [2] 95 d8 [2] db d4 [2] d7 de [2] c0 d5 [2] db 9b [2] e6 }

  condition:
    any of them
}