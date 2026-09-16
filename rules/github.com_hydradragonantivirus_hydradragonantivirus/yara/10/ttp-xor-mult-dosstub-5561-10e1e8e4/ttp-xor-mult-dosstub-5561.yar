rule TTP_XOR_MULT_DOSStub_5561 {
  strings:
    $key_5561 = { 01 09 [2] 75 11 [2] 32 13 [2] 75 02 [2] 3b 0e [2] 37 04 [2] 20 0f [2] 3b 41 [2] 06 }

  condition:
    any of them
}