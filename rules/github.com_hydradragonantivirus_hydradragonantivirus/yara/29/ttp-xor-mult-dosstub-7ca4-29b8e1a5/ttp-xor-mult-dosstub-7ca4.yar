rule TTP_XOR_MULT_DOSStub_7ca4 {
  strings:
    $key_7ca4 = { 28 cc [2] 5c d4 [2] 1b d6 [2] 5c c7 [2] 12 cb [2] 1e c1 [2] 09 ca [2] 12 84 [2] 2f }

  condition:
    any of them
}