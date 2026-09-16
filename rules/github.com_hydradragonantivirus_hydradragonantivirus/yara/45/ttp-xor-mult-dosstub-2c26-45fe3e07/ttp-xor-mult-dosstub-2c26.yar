rule TTP_XOR_MULT_DOSStub_2c26 {
  strings:
    $key_2c26 = { 78 4e [2] 0c 56 [2] 4b 54 [2] 0c 45 [2] 42 49 [2] 4e 43 [2] 59 48 [2] 42 06 [2] 7f }

  condition:
    any of them
}