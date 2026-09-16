rule TTP_XOR_MULT_DOSStub_2d26 {
  strings:
    $key_2d26 = { 79 4e [2] 0d 56 [2] 4a 54 [2] 0d 45 [2] 43 49 [2] 4f 43 [2] 58 48 [2] 43 06 [2] 7e }

  condition:
    any of them
}