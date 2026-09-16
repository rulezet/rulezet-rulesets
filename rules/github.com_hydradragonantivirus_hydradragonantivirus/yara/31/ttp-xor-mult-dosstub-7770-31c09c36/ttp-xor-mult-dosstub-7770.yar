rule TTP_XOR_MULT_DOSStub_7770 {
  strings:
    $key_7770 = { 23 18 [2] 57 00 [2] 10 02 [2] 57 13 [2] 19 1f [2] 15 15 [2] 02 1e [2] 19 50 [2] 24 }

  condition:
    any of them
}