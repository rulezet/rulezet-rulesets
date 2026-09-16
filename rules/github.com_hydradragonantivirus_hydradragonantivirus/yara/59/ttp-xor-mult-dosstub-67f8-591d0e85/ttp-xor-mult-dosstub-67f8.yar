rule TTP_XOR_MULT_DOSStub_67f8 {
  strings:
    $key_67f8 = { 33 90 [2] 47 88 [2] 00 8a [2] 47 9b [2] 09 97 [2] 05 9d [2] 12 96 [2] 09 d8 [2] 34 }

  condition:
    any of them
}