rule TTP_XOR_MULT_DOSStub_2544 {
  strings:
    $key_2544 = { 71 2c [2] 05 34 [2] 42 36 [2] 05 27 [2] 4b 2b [2] 47 21 [2] 50 2a [2] 4b 64 [2] 76 }

  condition:
    any of them
}