rule TTP_XOR_MULT_DOSStub_6764 {
  strings:
    $key_6764 = { 33 0c [2] 47 14 [2] 00 16 [2] 47 07 [2] 09 0b [2] 05 01 [2] 12 0a [2] 09 44 [2] 34 }

  condition:
    any of them
}