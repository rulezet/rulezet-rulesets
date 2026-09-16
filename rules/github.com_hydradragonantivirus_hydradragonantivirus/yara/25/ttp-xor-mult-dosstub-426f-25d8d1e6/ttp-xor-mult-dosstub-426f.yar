rule TTP_XOR_MULT_DOSStub_426f {
  strings:
    $key_426f = { 16 07 [2] 62 1f [2] 25 1d [2] 62 0c [2] 2c 00 [2] 20 0a [2] 37 01 [2] 2c 4f [2] 11 }

  condition:
    any of them
}