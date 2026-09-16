rule TTP_XOR_MULT_DOSStub_2d39 {
  strings:
    $key_2d39 = { 79 51 [2] 0d 49 [2] 4a 4b [2] 0d 5a [2] 43 56 [2] 4f 5c [2] 58 57 [2] 43 19 [2] 7e }

  condition:
    any of them
}