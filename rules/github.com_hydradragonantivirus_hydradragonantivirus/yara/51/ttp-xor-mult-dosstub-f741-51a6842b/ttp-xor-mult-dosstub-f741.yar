rule TTP_XOR_MULT_DOSStub_f741 {
  strings:
    $key_f741 = { a3 29 [2] d7 31 [2] 90 33 [2] d7 22 [2] 99 2e [2] 95 24 [2] 82 2f [2] 99 61 [2] a4 }

  condition:
    any of them
}