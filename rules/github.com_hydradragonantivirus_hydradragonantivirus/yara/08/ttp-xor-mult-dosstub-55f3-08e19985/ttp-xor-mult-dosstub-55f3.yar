rule TTP_XOR_MULT_DOSStub_55f3 {
  strings:
    $key_55f3 = { 01 9b [2] 75 83 [2] 32 81 [2] 75 90 [2] 3b 9c [2] 37 96 [2] 20 9d [2] 3b d3 [2] 06 }

  condition:
    any of them
}