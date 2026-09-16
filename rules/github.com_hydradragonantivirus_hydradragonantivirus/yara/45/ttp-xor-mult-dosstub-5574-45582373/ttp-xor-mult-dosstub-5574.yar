rule TTP_XOR_MULT_DOSStub_5574 {
  strings:
    $key_5574 = { 01 1c [2] 75 04 [2] 32 06 [2] 75 17 [2] 3b 1b [2] 37 11 [2] 20 1a [2] 3b 54 [2] 06 }

  condition:
    any of them
}