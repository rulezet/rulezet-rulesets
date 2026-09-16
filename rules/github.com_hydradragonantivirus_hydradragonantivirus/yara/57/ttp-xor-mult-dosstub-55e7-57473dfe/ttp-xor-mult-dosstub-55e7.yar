rule TTP_XOR_MULT_DOSStub_55e7 {
  strings:
    $key_55e7 = { 01 8f [2] 75 97 [2] 32 95 [2] 75 84 [2] 3b 88 [2] 37 82 [2] 20 89 [2] 3b c7 [2] 06 }

  condition:
    any of them
}