rule TTP_XOR_MULT_DOSStub_2442 {
  strings:
    $key_2442 = { 70 2a [2] 04 32 [2] 43 30 [2] 04 21 [2] 4a 2d [2] 46 27 [2] 51 2c [2] 4a 62 [2] 77 }

  condition:
    any of them
}