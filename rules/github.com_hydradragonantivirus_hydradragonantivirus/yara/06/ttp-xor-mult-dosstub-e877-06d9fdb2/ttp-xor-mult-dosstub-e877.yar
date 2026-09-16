rule TTP_XOR_MULT_DOSStub_e877 {
  strings:
    $key_e877 = { bc 1f [2] c8 07 [2] 8f 05 [2] c8 14 [2] 86 18 [2] 8a 12 [2] 9d 19 [2] 86 57 [2] bb }

  condition:
    any of them
}