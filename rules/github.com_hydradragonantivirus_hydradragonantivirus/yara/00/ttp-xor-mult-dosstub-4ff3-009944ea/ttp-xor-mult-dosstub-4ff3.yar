rule TTP_XOR_MULT_DOSStub_4ff3 {
  strings:
    $key_4ff3 = { 1b 9b [2] 6f 83 [2] 28 81 [2] 6f 90 [2] 21 9c [2] 2d 96 [2] 3a 9d [2] 21 d3 [2] 1c }

  condition:
    any of them
}