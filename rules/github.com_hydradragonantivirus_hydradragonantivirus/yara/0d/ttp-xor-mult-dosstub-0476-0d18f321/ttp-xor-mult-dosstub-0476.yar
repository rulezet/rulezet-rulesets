rule TTP_XOR_MULT_DOSStub_0476 {
  strings:
    $key_0476 = { 50 1e [2] 24 06 [2] 63 04 [2] 24 15 [2] 6a 19 [2] 66 13 [2] 71 18 [2] 6a 56 [2] 57 }

  condition:
    any of them
}