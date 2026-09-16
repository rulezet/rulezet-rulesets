rule TTP_XOR_MULT_DOSStub_5955 {
  strings:
    $key_5955 = { 0d 3d [2] 79 25 [2] 3e 27 [2] 79 36 [2] 37 3a [2] 3b 30 [2] 2c 3b [2] 37 75 [2] 0a }

  condition:
    any of them
}