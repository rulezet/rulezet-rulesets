rule TTP_XOR_MULT_DOSStub_75e7 {
  strings:
    $key_75e7 = { 21 8f [2] 55 97 [2] 12 95 [2] 55 84 [2] 1b 88 [2] 17 82 [2] 00 89 [2] 1b c7 [2] 26 }

  condition:
    any of them
}