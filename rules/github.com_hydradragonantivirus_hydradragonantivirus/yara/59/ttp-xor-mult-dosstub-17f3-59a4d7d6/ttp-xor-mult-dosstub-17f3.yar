rule TTP_XOR_MULT_DOSStub_17f3 {
  strings:
    $key_17f3 = { 43 9b [2] 37 83 [2] 70 81 [2] 37 90 [2] 79 9c [2] 75 96 [2] 62 9d [2] 79 d3 [2] 44 }

  condition:
    any of them
}