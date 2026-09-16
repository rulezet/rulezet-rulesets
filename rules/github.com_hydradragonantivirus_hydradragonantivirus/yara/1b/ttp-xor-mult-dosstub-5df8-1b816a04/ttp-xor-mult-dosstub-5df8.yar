rule TTP_XOR_MULT_DOSStub_5df8 {
  strings:
    $key_5df8 = { 09 90 [2] 7d 88 [2] 3a 8a [2] 7d 9b [2] 33 97 [2] 3f 9d [2] 28 96 [2] 33 d8 [2] 0e }

  condition:
    any of them
}