rule TTP_XOR_MULT_DOSStub_7ba3 {
  strings:
    $key_7ba3 = { 2f cb [2] 5b d3 [2] 1c d1 [2] 5b c0 [2] 15 cc [2] 19 c6 [2] 0e cd [2] 15 83 [2] 28 }

  condition:
    any of them
}