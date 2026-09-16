rule TTP_XOR_MULT_DOSStub_25f3 {
  strings:
    $key_25f3 = { 71 9b [2] 05 83 [2] 42 81 [2] 05 90 [2] 4b 9c [2] 47 96 [2] 50 9d [2] 4b d3 [2] 76 }

  condition:
    any of them
}