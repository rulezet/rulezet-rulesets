rule TTP_XOR_MULT_DOSStub_593f {
  strings:
    $key_593f = { 0d 57 [2] 79 4f [2] 3e 4d [2] 79 5c [2] 37 50 [2] 3b 5a [2] 2c 51 [2] 37 1f [2] 0a }

  condition:
    any of them
}