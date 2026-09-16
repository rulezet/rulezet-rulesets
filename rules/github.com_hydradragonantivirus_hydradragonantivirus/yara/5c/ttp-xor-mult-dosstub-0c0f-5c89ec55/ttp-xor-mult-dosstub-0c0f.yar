rule TTP_XOR_MULT_DOSStub_0c0f {
  strings:
    $key_0c0f = { 58 67 [2] 2c 7f [2] 6b 7d [2] 2c 6c [2] 62 60 [2] 6e 6a [2] 79 61 [2] 62 2f [2] 5f }

  condition:
    any of them
}