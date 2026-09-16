rule TTP_XOR_MULT_DOSStub_23f3 {
  strings:
    $key_23f3 = { 77 9b [2] 03 83 [2] 44 81 [2] 03 90 [2] 4d 9c [2] 41 96 [2] 56 9d [2] 4d d3 [2] 70 }

  condition:
    any of them
}