rule TTP_XOR_MULT_DOSStub_2d70 {
  strings:
    $key_2d70 = { 79 18 [2] 0d 00 [2] 4a 02 [2] 0d 13 [2] 43 1f [2] 4f 15 [2] 58 1e [2] 43 50 [2] 7e }

  condition:
    any of them
}