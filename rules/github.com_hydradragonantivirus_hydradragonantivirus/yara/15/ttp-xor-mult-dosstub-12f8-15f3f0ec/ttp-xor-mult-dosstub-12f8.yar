rule TTP_XOR_MULT_DOSStub_12f8 {
  strings:
    $key_12f8 = { 46 90 [2] 32 88 [2] 75 8a [2] 32 9b [2] 7c 97 [2] 70 9d [2] 67 96 [2] 7c d8 [2] 41 }

  condition:
    any of them
}