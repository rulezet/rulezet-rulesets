rule TTP_XOR_MULT_DOSStub_2c10 {
  strings:
    $key_2c10 = { 78 78 [2] 0c 60 [2] 4b 62 [2] 0c 73 [2] 42 7f [2] 4e 75 [2] 59 7e [2] 42 30 [2] 7f }

  condition:
    any of them
}