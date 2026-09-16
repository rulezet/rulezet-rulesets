rule TTP_XOR_MULT_DOSStub_3442 {
  strings:
    $key_3442 = { 60 2a [2] 14 32 [2] 53 30 [2] 14 21 [2] 5a 2d [2] 56 27 [2] 41 2c [2] 5a 62 [2] 67 }

  condition:
    any of them
}