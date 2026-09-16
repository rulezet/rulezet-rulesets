rule TTP_XOR_MULT_DOSStub_78e7 {
  strings:
    $key_78e7 = { 2c 8f [2] 58 97 [2] 1f 95 [2] 58 84 [2] 16 88 [2] 1a 82 [2] 0d 89 [2] 16 c7 [2] 2b }

  condition:
    any of them
}