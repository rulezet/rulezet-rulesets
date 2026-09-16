rule TTP_XOR_MULT_DOSStub_6375 {
  strings:
    $key_6375 = { 37 1d [2] 43 05 [2] 04 07 [2] 43 16 [2] 0d 1a [2] 01 10 [2] 16 1b [2] 0d 55 [2] 30 }

  condition:
    any of them
}