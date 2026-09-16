rule TTP_XOR_MULT_DOSStub_2c60 {
  strings:
    $key_2c60 = { 78 08 [2] 0c 10 [2] 4b 12 [2] 0c 03 [2] 42 0f [2] 4e 05 [2] 59 0e [2] 42 40 [2] 7f }

  condition:
    any of them
}