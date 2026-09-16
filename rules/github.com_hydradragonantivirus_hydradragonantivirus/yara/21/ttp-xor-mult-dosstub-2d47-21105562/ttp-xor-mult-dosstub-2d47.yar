rule TTP_XOR_MULT_DOSStub_2d47 {
  strings:
    $key_2d47 = { 79 2f [2] 0d 37 [2] 4a 35 [2] 0d 24 [2] 43 28 [2] 4f 22 [2] 58 29 [2] 43 67 [2] 7e }

  condition:
    any of them
}