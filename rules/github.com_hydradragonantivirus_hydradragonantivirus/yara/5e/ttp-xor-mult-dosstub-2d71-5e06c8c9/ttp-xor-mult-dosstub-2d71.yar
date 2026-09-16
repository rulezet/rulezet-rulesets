rule TTP_XOR_MULT_DOSStub_2d71 {
  strings:
    $key_2d71 = { 79 19 [2] 0d 01 [2] 4a 03 [2] 0d 12 [2] 43 1e [2] 4f 14 [2] 58 1f [2] 43 51 [2] 7e }

  condition:
    any of them
}