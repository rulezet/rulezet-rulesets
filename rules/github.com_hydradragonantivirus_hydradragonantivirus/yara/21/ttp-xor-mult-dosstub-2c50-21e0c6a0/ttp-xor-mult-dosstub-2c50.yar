rule TTP_XOR_MULT_DOSStub_2c50 {
  strings:
    $key_2c50 = { 78 38 [2] 0c 20 [2] 4b 22 [2] 0c 33 [2] 42 3f [2] 4e 35 [2] 59 3e [2] 42 70 [2] 7f }

  condition:
    any of them
}