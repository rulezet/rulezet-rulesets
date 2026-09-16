rule TTP_XOR_MULT_DOSStub_5437 {
  strings:
    $key_5437 = { 00 5f [2] 74 47 [2] 33 45 [2] 74 54 [2] 3a 58 [2] 36 52 [2] 21 59 [2] 3a 17 [2] 07 }

  condition:
    any of them
}