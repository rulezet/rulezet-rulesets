rule TTP_XOR_MULT_DOSStub_63f3 {
  strings:
    $key_63f3 = { 37 9b [2] 43 83 [2] 04 81 [2] 43 90 [2] 0d 9c [2] 01 96 [2] 16 9d [2] 0d d3 [2] 30 }

  condition:
    any of them
}