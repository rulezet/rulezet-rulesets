rule TTP_XOR_MULT_DOSStub_47f3 {
  strings:
    $key_47f3 = { 13 9b [2] 67 83 [2] 20 81 [2] 67 90 [2] 29 9c [2] 25 96 [2] 32 9d [2] 29 d3 [2] 14 }

  condition:
    any of them
}