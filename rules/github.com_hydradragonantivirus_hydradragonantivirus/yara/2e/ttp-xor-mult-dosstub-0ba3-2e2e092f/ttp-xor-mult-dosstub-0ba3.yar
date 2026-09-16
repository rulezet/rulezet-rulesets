rule TTP_XOR_MULT_DOSStub_0ba3 {
  strings:
    $key_0ba3 = { 5f cb [2] 2b d3 [2] 6c d1 [2] 2b c0 [2] 65 cc [2] 69 c6 [2] 7e cd [2] 65 83 [2] 58 }

  condition:
    any of them
}