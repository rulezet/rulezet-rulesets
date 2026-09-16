rule TTP_XOR_MULT_DOSStub_0c0c {
  strings:
    $key_0c0c = { 58 64 [2] 2c 7c [2] 6b 7e [2] 2c 6f [2] 62 63 [2] 6e 69 [2] 79 62 [2] 62 2c [2] 5f }

  condition:
    any of them
}