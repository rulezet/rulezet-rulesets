rule TTP_XOR_MULT_DOSStub_4770 {
  strings:
    $key_4770 = { 13 18 [2] 67 00 [2] 20 02 [2] 67 13 [2] 29 1f [2] 25 15 [2] 32 1e [2] 29 50 [2] 14 }

  condition:
    any of them
}