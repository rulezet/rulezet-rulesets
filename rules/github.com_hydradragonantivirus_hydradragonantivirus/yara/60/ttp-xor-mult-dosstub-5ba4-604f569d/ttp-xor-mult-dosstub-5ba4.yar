rule TTP_XOR_MULT_DOSStub_5ba4 {
  strings:
    $key_5ba4 = { 0f cc [2] 7b d4 [2] 3c d6 [2] 7b c7 [2] 35 cb [2] 39 c1 [2] 2e ca [2] 35 84 [2] 08 }

  condition:
    any of them
}