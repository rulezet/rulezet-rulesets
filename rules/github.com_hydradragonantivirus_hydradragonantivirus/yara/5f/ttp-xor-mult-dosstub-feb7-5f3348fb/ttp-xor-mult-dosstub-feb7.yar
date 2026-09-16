rule TTP_XOR_MULT_DOSStub_feb7 {
  strings:
    $key_feb7 = { aa df [2] de c7 [2] 99 c5 [2] de d4 [2] 90 d8 [2] 9c d2 [2] 8b d9 [2] 90 97 [2] ad }

  condition:
    any of them
}