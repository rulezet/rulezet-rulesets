rule TTP_XOR_MULT_DOSStub_7ba4 {
  strings:
    $key_7ba4 = { 2f cc [2] 5b d4 [2] 1c d6 [2] 5b c7 [2] 15 cb [2] 19 c1 [2] 0e ca [2] 15 84 [2] 28 }

  condition:
    any of them
}