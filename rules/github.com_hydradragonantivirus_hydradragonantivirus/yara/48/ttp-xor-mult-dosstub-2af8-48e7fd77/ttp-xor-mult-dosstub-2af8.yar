rule TTP_XOR_MULT_DOSStub_2af8 {
  strings:
    $key_2af8 = { 7e 90 [2] 0a 88 [2] 4d 8a [2] 0a 9b [2] 44 97 [2] 48 9d [2] 5f 96 [2] 44 d8 [2] 79 }

  condition:
    any of them
}