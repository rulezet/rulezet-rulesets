rule TTP_XOR_MULT_DOSStub_784b {
  strings:
    $key_784b = { 2c 23 [2] 58 3b [2] 1f 39 [2] 58 28 [2] 16 24 [2] 1a 2e [2] 0d 25 [2] 16 6b [2] 2b }

  condition:
    any of them
}