rule TTP_XOR_MULT_DOSStub_7820 {
  strings:
    $key_7820 = { 2c 48 [2] 58 50 [2] 1f 52 [2] 58 43 [2] 16 4f [2] 1a 45 [2] 0d 4e [2] 16 00 [2] 2b }

  condition:
    any of them
}