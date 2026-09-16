rule TTP_XOR_MULT_DOSStub_41f8 {
  strings:
    $key_41f8 = { 15 90 [2] 61 88 [2] 26 8a [2] 61 9b [2] 2f 97 [2] 23 9d [2] 34 96 [2] 2f d8 [2] 12 }

  condition:
    any of them
}