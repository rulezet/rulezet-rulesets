rule TTP_XOR_MULT_DOSStub_2c31 {
  strings:
    $key_2c31 = { 78 59 [2] 0c 41 [2] 4b 43 [2] 0c 52 [2] 42 5e [2] 4e 54 [2] 59 5f [2] 42 11 [2] 7f }

  condition:
    any of them
}