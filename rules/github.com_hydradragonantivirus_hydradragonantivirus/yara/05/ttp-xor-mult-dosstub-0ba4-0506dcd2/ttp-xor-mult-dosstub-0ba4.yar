rule TTP_XOR_MULT_DOSStub_0ba4 {
  strings:
    $key_0ba4 = { 5f cc [2] 2b d4 [2] 6c d6 [2] 2b c7 [2] 65 cb [2] 69 c1 [2] 7e ca [2] 65 84 [2] 58 }

  condition:
    any of them
}