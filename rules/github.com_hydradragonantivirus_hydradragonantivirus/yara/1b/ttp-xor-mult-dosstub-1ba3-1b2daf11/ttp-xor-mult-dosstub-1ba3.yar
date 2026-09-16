rule TTP_XOR_MULT_DOSStub_1ba3 {
  strings:
    $key_1ba3 = { 4f cb [2] 3b d3 [2] 7c d1 [2] 3b c0 [2] 75 cc [2] 79 c6 [2] 6e cd [2] 75 83 [2] 48 }

  condition:
    any of them
}