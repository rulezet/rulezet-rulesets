rule TTP_XOR_MULT_DOSStub_2d00 {
  strings:
    $key_2d00 = { 79 68 [2] 0d 70 [2] 4a 72 [2] 0d 63 [2] 43 6f [2] 4f 65 [2] 58 6e [2] 43 20 [2] 7e }

  condition:
    any of them
}