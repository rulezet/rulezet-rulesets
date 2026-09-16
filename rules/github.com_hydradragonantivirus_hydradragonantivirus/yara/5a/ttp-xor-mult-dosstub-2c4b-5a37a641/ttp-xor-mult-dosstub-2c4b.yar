rule TTP_XOR_MULT_DOSStub_2c4b {
  strings:
    $key_2c4b = { 78 23 [2] 0c 3b [2] 4b 39 [2] 0c 28 [2] 42 24 [2] 4e 2e [2] 59 25 [2] 42 6b [2] 7f }

  condition:
    any of them
}