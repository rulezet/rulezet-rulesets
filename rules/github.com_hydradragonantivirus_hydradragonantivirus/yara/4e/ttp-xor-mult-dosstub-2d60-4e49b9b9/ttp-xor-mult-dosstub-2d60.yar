rule TTP_XOR_MULT_DOSStub_2d60 {
  strings:
    $key_2d60 = { 79 08 [2] 0d 10 [2] 4a 12 [2] 0d 03 [2] 43 0f [2] 4f 05 [2] 58 0e [2] 43 40 [2] 7e }

  condition:
    any of them
}