rule TTP_XOR_MULT_DOSStub_7577 {
  strings:
    $key_7577 = { 21 1f [2] 55 07 [2] 12 05 [2] 55 14 [2] 1b 18 [2] 17 12 [2] 00 19 [2] 1b 57 [2] 26 }

  condition:
    any of them
}