rule TTP_XOR_MULT_DOSStub_4577 {
  strings:
    $key_4577 = { 11 1f [2] 65 07 [2] 22 05 [2] 65 14 [2] 2b 18 [2] 27 12 [2] 30 19 [2] 2b 57 [2] 16 }

  condition:
    any of them
}