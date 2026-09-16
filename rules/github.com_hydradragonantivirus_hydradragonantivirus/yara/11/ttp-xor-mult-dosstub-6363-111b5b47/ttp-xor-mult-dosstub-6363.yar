rule TTP_XOR_MULT_DOSStub_6363 {
  strings:
    $key_6363 = { 37 0b [2] 43 13 [2] 04 11 [2] 43 00 [2] 0d 0c [2] 01 06 [2] 16 0d [2] 0d 43 [2] 30 }

  condition:
    any of them
}