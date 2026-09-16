rule TTP_XOR_MULT_DOSStub_7764 {
  strings:
    $key_7764 = { 23 0c [2] 57 14 [2] 10 16 [2] 57 07 [2] 19 0b [2] 15 01 [2] 02 0a [2] 19 44 [2] 24 }

  condition:
    any of them
}