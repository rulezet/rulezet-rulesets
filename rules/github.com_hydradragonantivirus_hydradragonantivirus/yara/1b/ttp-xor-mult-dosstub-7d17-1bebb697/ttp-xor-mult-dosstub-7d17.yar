rule TTP_XOR_MULT_DOSStub_7d17 {
  strings:
    $key_7d17 = { 29 7f [2] 5d 67 [2] 1a 65 [2] 5d 74 [2] 13 78 [2] 1f 72 [2] 08 79 [2] 13 37 [2] 2e }

  condition:
    any of them
}