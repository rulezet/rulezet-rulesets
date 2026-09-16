rule TTP_XOR_MULT_DOSStub_20f3 {
  strings:
    $key_20f3 = { 74 9b [2] 00 83 [2] 47 81 [2] 00 90 [2] 4e 9c [2] 42 96 [2] 55 9d [2] 4e d3 [2] 73 }

  condition:
    any of them
}