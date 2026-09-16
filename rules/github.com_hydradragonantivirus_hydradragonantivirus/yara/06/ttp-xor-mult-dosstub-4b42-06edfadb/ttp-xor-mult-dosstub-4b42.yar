rule TTP_XOR_MULT_DOSStub_4b42 {
  strings:
    $key_4b42 = { 1f 2a [2] 6b 32 [2] 2c 30 [2] 6b 21 [2] 25 2d [2] 29 27 [2] 3e 2c [2] 25 62 [2] 18 }

  condition:
    any of them
}