rule TTP_XOR_MULT_DOSStub_5976 {
  strings:
    $key_5976 = { 0d 1e [2] 79 06 [2] 3e 04 [2] 79 15 [2] 37 19 [2] 3b 13 [2] 2c 18 [2] 37 56 [2] 0a }

  condition:
    any of them
}