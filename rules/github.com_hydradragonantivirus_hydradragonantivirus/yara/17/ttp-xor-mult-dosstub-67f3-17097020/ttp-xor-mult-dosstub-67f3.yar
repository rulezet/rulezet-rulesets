rule TTP_XOR_MULT_DOSStub_67f3 {
  strings:
    $key_67f3 = { 33 9b [2] 47 83 [2] 00 81 [2] 47 90 [2] 09 9c [2] 05 96 [2] 12 9d [2] 09 d3 [2] 34 }

  condition:
    any of them
}