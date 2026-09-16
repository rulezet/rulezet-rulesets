rule TTP_XOR_MULT_DOSStub_6344 {
  strings:
    $key_6344 = { 37 2c [2] 43 34 [2] 04 36 [2] 43 27 [2] 0d 2b [2] 01 21 [2] 16 2a [2] 0d 64 [2] 30 }

  condition:
    any of them
}