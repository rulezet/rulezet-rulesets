rule TTP_XOR_MULT_DOSStub_55f8 {
  strings:
    $key_55f8 = { 01 90 [2] 75 88 [2] 32 8a [2] 75 9b [2] 3b 97 [2] 37 9d [2] 20 96 [2] 3b d8 [2] 06 }

  condition:
    any of them
}