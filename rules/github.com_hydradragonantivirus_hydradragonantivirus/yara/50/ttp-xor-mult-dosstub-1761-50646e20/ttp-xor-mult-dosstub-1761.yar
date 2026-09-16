rule TTP_XOR_MULT_DOSStub_1761 {
  strings:
    $key_1761 = { 43 09 [2] 37 11 [2] 70 13 [2] 37 02 [2] 79 0e [2] 75 04 [2] 62 0f [2] 79 41 [2] 44 }

  condition:
    any of them
}