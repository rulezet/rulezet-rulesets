rule TTP_XOR_MULT_DOSStub_2ba4 {
  strings:
    $key_2ba4 = { 7f cc [2] 0b d4 [2] 4c d6 [2] 0b c7 [2] 45 cb [2] 49 c1 [2] 5e ca [2] 45 84 [2] 78 }

  condition:
    any of them
}