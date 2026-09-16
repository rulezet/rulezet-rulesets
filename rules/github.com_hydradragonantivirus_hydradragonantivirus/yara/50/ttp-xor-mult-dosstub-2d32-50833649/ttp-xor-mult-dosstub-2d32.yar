rule TTP_XOR_MULT_DOSStub_2d32 {
  strings:
    $key_2d32 = { 79 5a [2] 0d 42 [2] 4a 40 [2] 0d 51 [2] 43 5d [2] 4f 57 [2] 58 5c [2] 43 12 [2] 7e }

  condition:
    any of them
}