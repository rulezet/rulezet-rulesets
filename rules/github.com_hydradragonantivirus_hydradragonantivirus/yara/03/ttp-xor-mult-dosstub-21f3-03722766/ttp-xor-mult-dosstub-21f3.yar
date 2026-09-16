rule TTP_XOR_MULT_DOSStub_21f3 {
  strings:
    $key_21f3 = { 75 9b [2] 01 83 [2] 46 81 [2] 01 90 [2] 4f 9c [2] 43 96 [2] 54 9d [2] 4f d3 [2] 72 }

  condition:
    any of them
}