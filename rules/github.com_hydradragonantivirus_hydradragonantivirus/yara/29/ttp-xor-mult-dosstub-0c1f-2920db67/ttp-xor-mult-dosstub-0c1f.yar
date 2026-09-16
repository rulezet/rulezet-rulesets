rule TTP_XOR_MULT_DOSStub_0c1f {
  strings:
    $key_0c1f = { 58 77 [2] 2c 6f [2] 6b 6d [2] 2c 7c [2] 62 70 [2] 6e 7a [2] 79 71 [2] 62 3f [2] 5f }

  condition:
    any of them
}