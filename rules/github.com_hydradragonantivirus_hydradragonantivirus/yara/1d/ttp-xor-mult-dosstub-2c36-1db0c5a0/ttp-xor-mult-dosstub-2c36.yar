rule TTP_XOR_MULT_DOSStub_2c36 {
  strings:
    $key_2c36 = { 78 5e [2] 0c 46 [2] 4b 44 [2] 0c 55 [2] 42 59 [2] 4e 53 [2] 59 58 [2] 42 16 [2] 7f }

  condition:
    any of them
}