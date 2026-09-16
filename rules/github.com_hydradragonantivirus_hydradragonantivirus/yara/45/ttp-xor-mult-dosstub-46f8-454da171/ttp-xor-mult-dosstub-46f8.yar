rule TTP_XOR_MULT_DOSStub_46f8 {
  strings:
    $key_46f8 = { 12 90 [2] 66 88 [2] 21 8a [2] 66 9b [2] 28 97 [2] 24 9d [2] 33 96 [2] 28 d8 [2] 15 }

  condition:
    any of them
}