rule TTP_XOR_MULT_DOSStub_4258 {
  strings:
    $key_4258 = { 16 30 [2] 62 28 [2] 25 2a [2] 62 3b [2] 2c 37 [2] 20 3d [2] 37 36 [2] 2c 78 [2] 11 }

  condition:
    any of them
}