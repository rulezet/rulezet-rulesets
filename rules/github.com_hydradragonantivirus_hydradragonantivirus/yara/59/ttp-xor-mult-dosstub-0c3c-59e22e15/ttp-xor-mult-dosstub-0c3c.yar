rule TTP_XOR_MULT_DOSStub_0c3c {
  strings:
    $key_0c3c = { 58 54 [2] 2c 4c [2] 6b 4e [2] 2c 5f [2] 62 53 [2] 6e 59 [2] 79 52 [2] 62 1c [2] 5f }

  condition:
    any of them
}