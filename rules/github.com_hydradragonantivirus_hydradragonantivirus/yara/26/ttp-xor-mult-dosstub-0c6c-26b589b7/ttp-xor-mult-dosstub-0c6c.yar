rule TTP_XOR_MULT_DOSStub_0c6c {
  strings:
    $key_0c6c = { 58 04 [2] 2c 1c [2] 6b 1e [2] 2c 0f [2] 62 03 [2] 6e 09 [2] 79 02 [2] 62 4c [2] 5f }

  condition:
    any of them
}