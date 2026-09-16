rule TTP_XOR_MULT_DOSStub_4af8 {
  strings:
    $key_4af8 = { 1e 90 [2] 6a 88 [2] 2d 8a [2] 6a 9b [2] 24 97 [2] 28 9d [2] 3f 96 [2] 24 d8 [2] 19 }

  condition:
    any of them
}