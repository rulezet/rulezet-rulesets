rule TTP_XOR_MULT_DOSStub_7877 {
  strings:
    $key_7877 = { 2c 1f [2] 58 07 [2] 1f 05 [2] 58 14 [2] 16 18 [2] 1a 12 [2] 0d 19 [2] 16 57 [2] 2b }

  condition:
    any of them
}