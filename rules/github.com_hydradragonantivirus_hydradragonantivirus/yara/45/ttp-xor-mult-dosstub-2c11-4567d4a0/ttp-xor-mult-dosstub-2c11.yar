rule TTP_XOR_MULT_DOSStub_2c11 {
  strings:
    $key_2c11 = { 78 79 [2] 0c 61 [2] 4b 63 [2] 0c 72 [2] 42 7e [2] 4e 74 [2] 59 7f [2] 42 31 [2] 7f }

  condition:
    any of them
}