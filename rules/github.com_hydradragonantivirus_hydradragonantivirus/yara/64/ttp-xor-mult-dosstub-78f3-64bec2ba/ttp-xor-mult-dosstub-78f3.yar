rule TTP_XOR_MULT_DOSStub_78f3 {
  strings:
    $key_78f3 = { 2c 9b [2] 58 83 [2] 1f 81 [2] 58 90 [2] 16 9c [2] 1a 96 [2] 0d 9d [2] 16 d3 [2] 2b }

  condition:
    any of them
}