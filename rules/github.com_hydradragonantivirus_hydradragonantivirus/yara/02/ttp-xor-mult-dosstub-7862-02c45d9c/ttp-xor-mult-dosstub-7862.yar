rule TTP_XOR_MULT_DOSStub_7862 {
  strings:
    $key_7862 = { 2c 0a [2] 58 12 [2] 1f 10 [2] 58 01 [2] 16 0d [2] 1a 07 [2] 0d 0c [2] 16 42 [2] 2b }

  condition:
    any of them
}