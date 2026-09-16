rule TTP_XOR_MULT_DOSStub_2c7d {
  strings:
    $key_2c7d = { 78 15 [2] 0c 0d [2] 4b 0f [2] 0c 1e [2] 42 12 [2] 4e 18 [2] 59 13 [2] 42 5d [2] 7f }

  condition:
    any of them
}