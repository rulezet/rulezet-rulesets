rule TTP_XOR_MULT_DOSStub_62f3 {
  strings:
    $key_62f3 = { 36 9b [2] 42 83 [2] 05 81 [2] 42 90 [2] 0c 9c [2] 00 96 [2] 17 9d [2] 0c d3 [2] 31 }

  condition:
    any of them
}