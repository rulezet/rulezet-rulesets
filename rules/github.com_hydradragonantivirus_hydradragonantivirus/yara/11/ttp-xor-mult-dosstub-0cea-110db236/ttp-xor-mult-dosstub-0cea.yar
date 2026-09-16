rule TTP_XOR_MULT_DOSStub_0cea {
  strings:
    $key_0cea = { 58 82 [2] 2c 9a [2] 6b 98 [2] 2c 89 [2] 62 85 [2] 6e 8f [2] 79 84 [2] 62 ca [2] 5f }

  condition:
    any of them
}