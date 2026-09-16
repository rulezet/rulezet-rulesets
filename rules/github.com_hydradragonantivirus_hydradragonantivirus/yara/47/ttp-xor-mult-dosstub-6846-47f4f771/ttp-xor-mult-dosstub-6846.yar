rule TTP_XOR_MULT_DOSStub_6846 {
  strings:
    $key_6846 = { 3c 2e [2] 48 36 [2] 0f 34 [2] 48 25 [2] 06 29 [2] 0a 23 [2] 1d 28 [2] 06 66 [2] 3b }

  condition:
    any of them
}