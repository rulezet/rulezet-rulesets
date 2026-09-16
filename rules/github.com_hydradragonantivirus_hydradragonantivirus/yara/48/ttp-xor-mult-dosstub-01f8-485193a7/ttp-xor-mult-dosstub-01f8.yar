rule TTP_XOR_MULT_DOSStub_01f8 {
  strings:
    $key_01f8 = { 55 90 [2] 21 88 [2] 66 8a [2] 21 9b [2] 6f 97 [2] 63 9d [2] 74 96 [2] 6f d8 [2] 52 }

  condition:
    any of them
}