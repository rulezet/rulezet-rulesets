rule TTP_XOR_MULT_DOSStub_5958 {
  strings:
    $key_5958 = { 0d 30 [2] 79 28 [2] 3e 2a [2] 79 3b [2] 37 37 [2] 3b 3d [2] 2c 36 [2] 37 78 [2] 0a }

  condition:
    any of them
}