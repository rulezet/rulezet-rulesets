rule TTP_XOR_MULT_DOSStub_5440 {
  strings:
    $key_5440 = { 00 28 [2] 74 30 [2] 33 32 [2] 74 23 [2] 3a 2f [2] 36 25 [2] 21 2e [2] 3a 60 [2] 07 }

  condition:
    any of them
}