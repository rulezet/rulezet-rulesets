rule TTP_XOR_MULT_DOSStub_a776 {
  strings:
    $key_a776 = { f3 1e [2] 87 06 [2] c0 04 [2] 87 15 [2] c9 19 [2] c5 13 [2] d2 18 [2] c9 56 [2] f4 }

  condition:
    any of them
}