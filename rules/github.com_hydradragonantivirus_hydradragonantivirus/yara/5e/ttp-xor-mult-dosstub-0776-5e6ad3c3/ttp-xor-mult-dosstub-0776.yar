rule TTP_XOR_MULT_DOSStub_0776 {
  strings:
    $key_0776 = { 53 1e [2] 27 06 [2] 60 04 [2] 27 15 [2] 69 19 [2] 65 13 [2] 72 18 [2] 69 56 [2] 54 }

  condition:
    any of them
}