rule TTP_XOR_MULT_DOSStub_3649 {
  strings:
    $key_3649 = { 62 21 [2] 16 39 [2] 51 3b [2] 16 2a [2] 58 26 [2] 54 2c [2] 43 27 [2] 58 69 [2] 65 }

  condition:
    any of them
}