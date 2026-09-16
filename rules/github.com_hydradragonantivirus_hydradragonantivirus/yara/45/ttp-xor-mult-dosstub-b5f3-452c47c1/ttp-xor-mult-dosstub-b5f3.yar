rule TTP_XOR_MULT_DOSStub_b5f3 {
  strings:
    $key_b5f3 = { e1 9b [2] 95 83 [2] d2 81 [2] 95 90 [2] db 9c [2] d7 96 [2] c0 9d [2] db d3 [2] e6 }

  condition:
    any of them
}