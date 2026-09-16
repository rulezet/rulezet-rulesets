rule TTP_XOR_MULT_DOSStub_6cf3 {
  strings:
    $key_6cf3 = { 38 9b [2] 4c 83 [2] 0b 81 [2] 4c 90 [2] 02 9c [2] 0e 96 [2] 19 9d [2] 02 d3 [2] 3f }

  condition:
    any of them
}