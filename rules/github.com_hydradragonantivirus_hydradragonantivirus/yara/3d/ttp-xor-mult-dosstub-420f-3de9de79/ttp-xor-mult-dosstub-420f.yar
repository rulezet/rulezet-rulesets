rule TTP_XOR_MULT_DOSStub_420f {
  strings:
    $key_420f = { 16 67 [2] 62 7f [2] 25 7d [2] 62 6c [2] 2c 60 [2] 20 6a [2] 37 61 [2] 2c 2f [2] 11 }

  condition:
    any of them
}