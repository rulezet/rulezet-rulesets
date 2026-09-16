rule TTP_XOR_MULT_DOSStub_2d15 {
  strings:
    $key_2d15 = { 79 7d [2] 0d 65 [2] 4a 67 [2] 0d 76 [2] 43 7a [2] 4f 70 [2] 58 7b [2] 43 35 [2] 7e }

  condition:
    any of them
}