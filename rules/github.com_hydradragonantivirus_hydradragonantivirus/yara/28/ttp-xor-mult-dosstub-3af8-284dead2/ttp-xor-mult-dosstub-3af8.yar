rule TTP_XOR_MULT_DOSStub_3af8 {
  strings:
    $key_3af8 = { 6e 90 [2] 1a 88 [2] 5d 8a [2] 1a 9b [2] 54 97 [2] 58 9d [2] 4f 96 [2] 54 d8 [2] 69 }

  condition:
    any of them
}