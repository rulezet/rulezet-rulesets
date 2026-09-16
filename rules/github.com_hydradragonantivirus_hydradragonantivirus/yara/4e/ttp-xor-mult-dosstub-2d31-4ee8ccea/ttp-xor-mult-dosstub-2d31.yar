rule TTP_XOR_MULT_DOSStub_2d31 {
  strings:
    $key_2d31 = { 79 59 [2] 0d 41 [2] 4a 43 [2] 0d 52 [2] 43 5e [2] 4f 54 [2] 58 5f [2] 43 11 [2] 7e }

  condition:
    any of them
}