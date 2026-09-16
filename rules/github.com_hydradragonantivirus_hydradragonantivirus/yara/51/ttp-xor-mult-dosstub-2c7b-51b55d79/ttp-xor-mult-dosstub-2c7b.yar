rule TTP_XOR_MULT_DOSStub_2c7b {
  strings:
    $key_2c7b = { 78 13 [2] 0c 0b [2] 4b 09 [2] 0c 18 [2] 42 14 [2] 4e 1e [2] 59 15 [2] 42 5b [2] 7f }

  condition:
    any of them
}