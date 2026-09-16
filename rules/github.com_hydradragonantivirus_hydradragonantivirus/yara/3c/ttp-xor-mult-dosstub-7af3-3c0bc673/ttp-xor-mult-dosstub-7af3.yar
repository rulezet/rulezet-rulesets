rule TTP_XOR_MULT_DOSStub_7af3 {
  strings:
    $key_7af3 = { 2e 9b [2] 5a 83 [2] 1d 81 [2] 5a 90 [2] 14 9c [2] 18 96 [2] 0f 9d [2] 14 d3 [2] 29 }

  condition:
    any of them
}