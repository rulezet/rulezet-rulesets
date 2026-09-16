rule TTP_XOR_MULT_DOSStub_7ff3 {
  strings:
    $key_7ff3 = { 2b 9b [2] 5f 83 [2] 18 81 [2] 5f 90 [2] 11 9c [2] 1d 96 [2] 0a 9d [2] 11 d3 [2] 2c }

  condition:
    any of them
}