rule TTP_XOR_MULT_DOSStub_596f {
  strings:
    $key_596f = { 0d 07 [2] 79 1f [2] 3e 1d [2] 79 0c [2] 37 00 [2] 3b 0a [2] 2c 01 [2] 37 4f [2] 0a }

  condition:
    any of them
}