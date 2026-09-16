rule TTP_XOR_MULT_DOSStub_0cee {
  strings:
    $key_0cee = { 58 86 [2] 2c 9e [2] 6b 9c [2] 2c 8d [2] 62 81 [2] 6e 8b [2] 79 80 [2] 62 ce [2] 5f }

  condition:
    any of them
}