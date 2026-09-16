rule TTP_XOR_MULT_DOSStub_75f3 {
  strings:
    $key_75f3 = { 21 9b [2] 55 83 [2] 12 81 [2] 55 90 [2] 1b 9c [2] 17 96 [2] 00 9d [2] 1b d3 [2] 26 }

  condition:
    any of them
}