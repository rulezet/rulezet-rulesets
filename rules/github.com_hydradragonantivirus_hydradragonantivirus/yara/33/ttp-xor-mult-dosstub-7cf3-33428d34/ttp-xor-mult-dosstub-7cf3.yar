rule TTP_XOR_MULT_DOSStub_7cf3 {
  strings:
    $key_7cf3 = { 28 9b [2] 5c 83 [2] 1b 81 [2] 5c 90 [2] 12 9c [2] 1e 96 [2] 09 9d [2] 12 d3 [2] 2f }

  condition:
    any of them
}