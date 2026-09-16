rule TTP_XOR_MULT_DOSStub_33f3 {
  strings:
    $key_33f3 = { 67 9b [2] 13 83 [2] 54 81 [2] 13 90 [2] 5d 9c [2] 51 96 [2] 46 9d [2] 5d d3 [2] 60 }

  condition:
    any of them
}