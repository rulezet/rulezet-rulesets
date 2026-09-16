rule TTP_XOR_MULT_DOSStub_5420 {
  strings:
    $key_5420 = { 00 48 [2] 74 50 [2] 33 52 [2] 74 43 [2] 3a 4f [2] 36 45 [2] 21 4e [2] 3a 00 [2] 07 }

  condition:
    any of them
}