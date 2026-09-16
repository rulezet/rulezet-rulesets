rule TTP_XOR_MULT_DOSStub_31f8 {
  strings:
    $key_31f8 = { 65 90 [2] 11 88 [2] 56 8a [2] 11 9b [2] 5f 97 [2] 53 9d [2] 44 96 [2] 5f d8 [2] 62 }

  condition:
    any of them
}