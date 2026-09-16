rule TTP_XOR_MULT_DOSStub_4ef8 {
  strings:
    $key_4ef8 = { 1a 90 [2] 6e 88 [2] 29 8a [2] 6e 9b [2] 20 97 [2] 2c 9d [2] 3b 96 [2] 20 d8 [2] 1d }

  condition:
    any of them
}