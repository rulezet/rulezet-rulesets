rule TTP_XOR_MULT_DOSStub_0576 {
  strings:
    $key_0576 = { 51 1e [2] 25 06 [2] 62 04 [2] 25 15 [2] 6b 19 [2] 67 13 [2] 70 18 [2] 6b 56 [2] 56 }

  condition:
    any of them
}