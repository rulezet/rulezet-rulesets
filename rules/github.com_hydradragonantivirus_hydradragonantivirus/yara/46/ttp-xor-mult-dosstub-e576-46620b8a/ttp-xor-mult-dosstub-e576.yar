rule TTP_XOR_MULT_DOSStub_e576 {
  strings:
    $key_e576 = { b1 1e [2] c5 06 [2] 82 04 [2] c5 15 [2] 8b 19 [2] 87 13 [2] 90 18 [2] 8b 56 [2] b6 }

  condition:
    any of them
}