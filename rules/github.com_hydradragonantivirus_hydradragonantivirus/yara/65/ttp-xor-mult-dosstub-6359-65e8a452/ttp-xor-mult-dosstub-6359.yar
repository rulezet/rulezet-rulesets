rule TTP_XOR_MULT_DOSStub_6359 {
  strings:
    $key_6359 = { 37 31 [2] 43 29 [2] 04 2b [2] 43 3a [2] 0d 36 [2] 01 3c [2] 16 37 [2] 0d 79 [2] 30 }

  condition:
    any of them
}