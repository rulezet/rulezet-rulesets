rule TTP_XOR_MULT_DOSStub_03f8 {
  strings:
    $key_03f8 = { 57 90 [2] 23 88 [2] 64 8a [2] 23 9b [2] 6d 97 [2] 61 9d [2] 76 96 [2] 6d d8 [2] 50 }

  condition:
    any of them
}