rule TTP_XOR_MULT_DOSStub_785b {
  strings:
    $key_785b = { 2c 33 [2] 58 2b [2] 1f 29 [2] 58 38 [2] 16 34 [2] 1a 3e [2] 0d 35 [2] 16 7b [2] 2b }

  condition:
    any of them
}