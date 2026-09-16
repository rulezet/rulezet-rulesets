rule TTP_XOR_MULT_DOSStub_2d34 {
  strings:
    $key_2d34 = { 79 5c [2] 0d 44 [2] 4a 46 [2] 0d 57 [2] 43 5b [2] 4f 51 [2] 58 5a [2] 43 14 [2] 7e }

  condition:
    any of them
}