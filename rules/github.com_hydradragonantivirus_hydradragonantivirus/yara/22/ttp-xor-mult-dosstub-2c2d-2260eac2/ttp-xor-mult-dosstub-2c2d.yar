rule TTP_XOR_MULT_DOSStub_2c2d {
  strings:
    $key_2c2d = { 78 45 [2] 0c 5d [2] 4b 5f [2] 0c 4e [2] 42 42 [2] 4e 48 [2] 59 43 [2] 42 0d [2] 7f }

  condition:
    any of them
}