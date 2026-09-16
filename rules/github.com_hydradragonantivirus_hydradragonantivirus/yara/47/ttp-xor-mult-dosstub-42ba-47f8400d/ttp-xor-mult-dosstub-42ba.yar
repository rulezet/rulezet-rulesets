rule TTP_XOR_MULT_DOSStub_42ba {
  strings:
    $key_42ba = { 16 d2 [2] 62 ca [2] 25 c8 [2] 62 d9 [2] 2c d5 [2] 20 df [2] 37 d4 [2] 2c 9a [2] 11 }

  condition:
    any of them
}