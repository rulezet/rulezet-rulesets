rule TTP_XOR_MULT_DOSStub_49f3 {
  strings:
    $key_49f3 = { 1d 9b [2] 69 83 [2] 2e 81 [2] 69 90 [2] 27 9c [2] 2b 96 [2] 3c 9d [2] 27 d3 [2] 1a }

  condition:
    any of them
}