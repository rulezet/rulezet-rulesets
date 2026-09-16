rule TTP_XOR_MULT_DOSStub_3776 {
  strings:
    $key_3776 = { 63 1e [2] 17 06 [2] 50 04 [2] 17 15 [2] 59 19 [2] 55 13 [2] 42 18 [2] 59 56 [2] 64 }

  condition:
    any of them
}