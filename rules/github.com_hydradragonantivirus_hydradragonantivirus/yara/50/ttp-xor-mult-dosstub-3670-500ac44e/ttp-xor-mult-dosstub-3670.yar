rule TTP_XOR_MULT_DOSStub_3670 {
  strings:
    $key_3670 = { 62 18 [2] 16 00 [2] 51 02 [2] 16 13 [2] 58 1f [2] 54 15 [2] 43 1e [2] 58 50 [2] 65 }

  condition:
    any of them
}