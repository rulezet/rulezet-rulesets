rule TTP_XOR_MULT_DOSStub_3b42 {
  strings:
    $key_3b42 = { 6f 2a [2] 1b 32 [2] 5c 30 [2] 1b 21 [2] 55 2d [2] 59 27 [2] 4e 2c [2] 55 62 [2] 68 }

  condition:
    any of them
}