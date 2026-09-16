rule TTP_XOR_MULT_DOSStub_2c7f {
  strings:
    $key_2c7f = { 78 17 [2] 0c 0f [2] 4b 0d [2] 0c 1c [2] 42 10 [2] 4e 1a [2] 59 11 [2] 42 5f [2] 7f }

  condition:
    any of them
}