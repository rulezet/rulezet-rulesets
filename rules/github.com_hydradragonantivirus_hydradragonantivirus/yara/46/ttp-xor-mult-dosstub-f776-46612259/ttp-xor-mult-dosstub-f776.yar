rule TTP_XOR_MULT_DOSStub_f776 {
  strings:
    $key_f776 = { a3 1e [2] d7 06 [2] 90 04 [2] d7 15 [2] 99 19 [2] 95 13 [2] 82 18 [2] 99 56 [2] a4 }

  condition:
    any of them
}