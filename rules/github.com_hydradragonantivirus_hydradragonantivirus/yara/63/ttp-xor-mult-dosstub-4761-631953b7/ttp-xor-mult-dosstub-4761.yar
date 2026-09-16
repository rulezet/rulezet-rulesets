rule TTP_XOR_MULT_DOSStub_4761 {
  strings:
    $key_4761 = { 13 09 [2] 67 11 [2] 20 13 [2] 67 02 [2] 29 0e [2] 25 04 [2] 32 0f [2] 29 41 [2] 14 }

  condition:
    any of them
}