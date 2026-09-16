rule TTP_XOR_MULT_DOSStub_2c3f {
  strings:
    $key_2c3f = { 78 57 [2] 0c 4f [2] 4b 4d [2] 0c 5c [2] 42 50 [2] 4e 5a [2] 59 51 [2] 42 1f [2] 7f }

  condition:
    any of them
}