rule TTP_XOR_MULT_DOSStub_70f3 {
  strings:
    $key_70f3 = { 24 9b [2] 50 83 [2] 17 81 [2] 50 90 [2] 1e 9c [2] 12 96 [2] 05 9d [2] 1e d3 [2] 23 }

  condition:
    any of them
}