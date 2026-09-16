rule TTP_XOR_MULT_DOSStub_7841 {
  strings:
    $key_7841 = { 2c 29 [2] 58 31 [2] 1f 33 [2] 58 22 [2] 16 2e [2] 1a 24 [2] 0d 2f [2] 16 61 [2] 2b }

  condition:
    any of them
}