rule TTP_XOR_MULT_DOSStub_0770 {
  strings:
    $key_0770 = { 53 18 [2] 27 00 [2] 60 02 [2] 27 13 [2] 69 1f [2] 65 15 [2] 72 1e [2] 69 50 [2] 54 }

  condition:
    any of them
}