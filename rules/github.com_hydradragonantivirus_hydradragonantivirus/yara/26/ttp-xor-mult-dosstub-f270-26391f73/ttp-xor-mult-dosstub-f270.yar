rule TTP_XOR_MULT_DOSStub_f270 {
  strings:
    $key_f270 = { a6 18 [2] d2 00 [2] 95 02 [2] d2 13 [2] 9c 1f [2] 90 15 [2] 87 1e [2] 9c 50 [2] a1 }

  condition:
    any of them
}