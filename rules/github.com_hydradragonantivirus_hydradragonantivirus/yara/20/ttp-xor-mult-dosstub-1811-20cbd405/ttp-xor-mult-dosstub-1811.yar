rule TTP_XOR_MULT_DOSStub_1811 {
  strings:
    $key_1811 = { 4c 79 [2] 38 61 [2] 7f 63 [2] 38 72 [2] 76 7e [2] 7a 74 [2] 6d 7f [2] 76 31 [2] 4b }

  condition:
    any of them
}