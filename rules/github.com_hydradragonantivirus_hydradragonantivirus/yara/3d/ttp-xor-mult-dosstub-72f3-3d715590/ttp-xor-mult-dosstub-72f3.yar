rule TTP_XOR_MULT_DOSStub_72f3 {
  strings:
    $key_72f3 = { 26 9b [2] 52 83 [2] 15 81 [2] 52 90 [2] 1c 9c [2] 10 96 [2] 07 9d [2] 1c d3 [2] 21 }

  condition:
    any of them
}