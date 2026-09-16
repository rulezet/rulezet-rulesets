rule TTP_XOR_MULT_DOSStub_4ba4 {
  strings:
    $key_4ba4 = { 1f cc [2] 6b d4 [2] 2c d6 [2] 6b c7 [2] 25 cb [2] 29 c1 [2] 3e ca [2] 25 84 [2] 18 }

  condition:
    any of them
}