rule TTP_XOR_MULT_DOSStub_18f3 {
  strings:
    $key_18f3 = { 4c 9b [2] 38 83 [2] 7f 81 [2] 38 90 [2] 76 9c [2] 7a 96 [2] 6d 9d [2] 76 d3 [2] 4b }

  condition:
    any of them
}