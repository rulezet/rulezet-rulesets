rule TTP_XOR_MULT_DOSStub_2c57 {
  strings:
    $key_2c57 = { 78 3f [2] 0c 27 [2] 4b 25 [2] 0c 34 [2] 42 38 [2] 4e 32 [2] 59 39 [2] 42 77 [2] 7f }

  condition:
    any of them
}