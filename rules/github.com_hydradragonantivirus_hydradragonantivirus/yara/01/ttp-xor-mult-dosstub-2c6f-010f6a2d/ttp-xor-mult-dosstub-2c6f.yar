rule TTP_XOR_MULT_DOSStub_2c6f {
  strings:
    $key_2c6f = { 78 07 [2] 0c 1f [2] 4b 1d [2] 0c 0c [2] 42 00 [2] 4e 0a [2] 59 01 [2] 42 4f [2] 7f }

  condition:
    any of them
}