rule TTP_XOR_MULT_DOSStub_0c77 {
  strings:
    $key_0c77 = { 58 1f [2] 2c 07 [2] 6b 05 [2] 2c 14 [2] 62 18 [2] 6e 12 [2] 79 19 [2] 62 57 [2] 5f }

  condition:
    any of them
}