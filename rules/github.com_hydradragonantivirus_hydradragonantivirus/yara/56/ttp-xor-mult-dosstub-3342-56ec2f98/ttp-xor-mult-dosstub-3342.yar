rule TTP_XOR_MULT_DOSStub_3342 {
  strings:
    $key_3342 = { 67 2a [2] 13 32 [2] 54 30 [2] 13 21 [2] 5d 2d [2] 51 27 [2] 46 2c [2] 5d 62 [2] 60 }

  condition:
    any of them
}