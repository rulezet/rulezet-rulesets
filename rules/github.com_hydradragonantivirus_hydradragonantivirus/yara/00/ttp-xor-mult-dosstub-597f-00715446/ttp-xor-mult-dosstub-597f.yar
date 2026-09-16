rule TTP_XOR_MULT_DOSStub_597f {
  strings:
    $key_597f = { 0d 17 [2] 79 0f [2] 3e 0d [2] 79 1c [2] 37 10 [2] 3b 1a [2] 2c 11 [2] 37 5f [2] 0a }

  condition:
    any of them
}