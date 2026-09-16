rule TTP_XOR_MULT_DOSStub_5537 {
  strings:
    $key_5537 = { 01 5f [2] 75 47 [2] 32 45 [2] 75 54 [2] 3b 58 [2] 37 52 [2] 20 59 [2] 3b 17 [2] 06 }

  condition:
    any of them
}