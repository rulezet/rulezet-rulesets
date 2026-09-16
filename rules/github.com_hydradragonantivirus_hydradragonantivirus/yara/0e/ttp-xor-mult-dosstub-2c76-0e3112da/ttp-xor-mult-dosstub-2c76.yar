rule TTP_XOR_MULT_DOSStub_2c76 {
  strings:
    $key_2c76 = { 78 1e [2] 0c 06 [2] 4b 04 [2] 0c 15 [2] 42 19 [2] 4e 13 [2] 59 18 [2] 42 56 [2] 7f }

  condition:
    any of them
}