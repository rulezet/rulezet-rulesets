rule TTP_XOR_MULT_DOSStub_2d06 {
  strings:
    $key_2d06 = { 79 6e [2] 0d 76 [2] 4a 74 [2] 0d 65 [2] 43 69 [2] 4f 63 [2] 58 68 [2] 43 26 [2] 7e }

  condition:
    any of them
}