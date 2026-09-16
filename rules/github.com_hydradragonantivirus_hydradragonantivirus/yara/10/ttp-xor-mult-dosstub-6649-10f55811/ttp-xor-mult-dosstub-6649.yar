rule TTP_XOR_MULT_DOSStub_6649 {
  strings:
    $key_6649 = { 32 21 [2] 46 39 [2] 01 3b [2] 46 2a [2] 08 26 [2] 04 2c [2] 13 27 [2] 08 69 [2] 35 }

  condition:
    any of them
}