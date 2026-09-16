rule TTP_XOR_MULT_DOSStub_42ea {
  strings:
    $key_42ea = { 16 82 [2] 62 9a [2] 25 98 [2] 62 89 [2] 2c 85 [2] 20 8f [2] 37 84 [2] 2c ca [2] 11 }

  condition:
    any of them
}