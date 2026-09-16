rule TTP_XOR_MULT_DOSStub_6847 {
  strings:
    $key_6847 = { 3c 2f [2] 48 37 [2] 0f 35 [2] 48 24 [2] 06 28 [2] 0a 22 [2] 1d 29 [2] 06 67 [2] 3b }

  condition:
    any of them
}