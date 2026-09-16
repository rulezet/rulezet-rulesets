rule TTP_XOR_MULT_DOSStub_2c66 {
  strings:
    $key_2c66 = { 78 0e [2] 0c 16 [2] 4b 14 [2] 0c 05 [2] 42 09 [2] 4e 03 [2] 59 08 [2] 42 46 [2] 7f }

  condition:
    any of them
}