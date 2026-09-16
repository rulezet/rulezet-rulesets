rule TTP_XOR_MULT_DOSStub_6642 {
  strings:
    $key_6642 = { 32 2a [2] 46 32 [2] 01 30 [2] 46 21 [2] 08 2d [2] 04 27 [2] 13 2c [2] 08 62 [2] 35 }

  condition:
    any of them
}