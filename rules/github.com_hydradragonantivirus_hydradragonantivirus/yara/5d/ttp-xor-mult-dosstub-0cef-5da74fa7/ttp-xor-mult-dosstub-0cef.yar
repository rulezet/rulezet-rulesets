rule TTP_XOR_MULT_DOSStub_0cef {
  strings:
    $key_0cef = { 58 87 [2] 2c 9f [2] 6b 9d [2] 2c 8c [2] 62 80 [2] 6e 8a [2] 79 81 [2] 62 cf [2] 5f }

  condition:
    any of them
}